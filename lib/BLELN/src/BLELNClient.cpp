//
// Created by dkulpa on 17.08.2025.
//

#include "BLELNClient.h"

#include <utility>

void BLELNClient::start(const std::string &name, std::function<void(const std::string&)> onServerResponse) {
    BLELNBase::rng_init();
    NimBLEDevice::init(name);
    NimBLEDevice::setSecurityAuth(true,true,true);
    NimBLEDevice::setSecurityIOCap(BLE_HS_IO_KEYBOARD_ONLY);
    NimBLEDevice::setMTU(247);
    g_rxQueue = xQueueCreate(20, sizeof(RxClientPacket));
    onMsgRx= std::move(onServerResponse);
    runRxWorker= true;
    xTaskCreatePinnedToCore(
            [](void* arg){
                static_cast<BLELNClient*>(arg)->rxWorker();
                vTaskDelete(nullptr);
            },
            "BLELNrx", 3072, this, 5, nullptr, 1);
}

void BLELNClient::stop() {
    if (scanning) {
        NimBLEScan* scan = NimBLEDevice::getScan();
        if(scan)
            scan->stop();
        scanning = false;
        onScanResult = nullptr;
    }

    runRxWorker= false;
    if(g_rxQueue)
        xQueueReset(g_rxQueue);

    if(chKeyExTx)
        chKeyExTx->unsubscribe(true);
    if(chDataTx)
        chDataTx ->unsubscribe(true);

    if(client!= nullptr){
        client->disconnect();
        NimBLEDevice::deleteClient(client);
        client= nullptr;
    }

    chKeyExTx = nullptr;
    chKeyExRx = nullptr;
    chDataTx  = nullptr;
    chDataRx  = nullptr;
    svc       = nullptr;

    onMsgRx = nullptr;

    s_sid = 0;
    s_ctr_s2c = 0;
    s_ctr_c2s = 0;
    memset(s_sessKey_s2c, 0, sizeof(s_sessKey_s2c));
    memset(s_sessKey_c2s, 0, sizeof(s_sessKey_c2s));
    memset(s_cliPub, 0, sizeof(s_cliPub));
    memset(s_srvPub, 0, sizeof(s_srvPub));
    memset(s_cliNonce, 0, sizeof(s_cliNonce));
    memset(s_srvNonce, 0, sizeof(s_srvNonce));
    memset(s_salt, 0, sizeof(s_salt));
    s_epoch = 0;
    g_keyexPayload.clear();
    g_keyexReady = false;

    NimBLEDevice::deinit(true);
}

void BLELNClient::startServerSearch(uint32_t durationMs, const std::string &serverUUID, const std::function<void(const NimBLEAdvertisedDevice *advertisedDevice)>& onResult) {
    scanning = true;
    onScanResult= onResult;
    searchedUUID= serverUUID;
    auto* scan=NimBLEDevice::getScan();
    scan->setScanCallbacks(this, false);
    scan->setActiveScan(true);
    scan->start(durationMs, false, false);
}

void BLELNClient::beginConnect(const NimBLEAdvertisedDevice *advertisedDevice, const std::function<void(bool, int)> &onConnectResult) {
    scanning = false;
    onConRes= onConnectResult;
    NimBLEDevice::getScan()->stop();
    client = NimBLEDevice::createClient();
    client->setClientCallbacks(this, false);
    client->connect(advertisedDevice, true, true, true);
}


void BLELNClient::onDiscovered(const NimBLEAdvertisedDevice *advertisedDevice) {
    Serial.println(advertisedDevice->toString().c_str());
}

void BLELNClient::onResult(const NimBLEAdvertisedDevice *advertisedDevice) {
    if (advertisedDevice->isAdvertisingService(NimBLEUUID(searchedUUID))) {
        scanning = false;
        if(onScanResult){
            onScanResult(advertisedDevice);
        }
    }
}

void BLELNClient::onScanEnd(const NimBLEScanResults &scanResults, int reason) {
    scanning = false;
    if(onScanResult){
        onScanResult(nullptr);
    }
}

bool BLELNClient::discover() {
    auto* s = client->getService(BLELNBase::SERVICE_UUID);
    if(!s)
        return false;
    svc=s;
    chKeyExTx = s->getCharacteristic(BLELNBase::KEYEX_TX_UUID);
    chKeyExRx = s->getCharacteristic(BLELNBase::KEYEX_RX_UUID);
    chDataTx  = s->getCharacteristic(BLELNBase::DATA_TX_UUID);
    chDataRx  = s->getCharacteristic(BLELNBase::DATA_RX_UUID);

    if(chKeyExTx && chKeyExRx && chDataTx && chDataRx) {
        chKeyExTx->subscribe(true,
                             [this](NimBLERemoteCharacteristic *pBLERemoteCharacteristic, uint8_t *pData, size_t length,
                                    bool isNotify) {
                                 this->onKeyExNotifyClb(pBLERemoteCharacteristic, pData, length, isNotify);
                             });
        chDataTx->subscribe(true,
                            [this](NimBLERemoteCharacteristic *pBLERemoteCharacteristic, uint8_t *pData, size_t length,
                                   bool isNotify) {
                                this->onServerResponse(pBLERemoteCharacteristic, pData, length, isNotify);
                            });
    }

    return chKeyExTx && chKeyExRx && chDataTx && chDataRx;
}

// TODO: Make nonblocking, rename "tryHandshake"
bool BLELNClient::handshake() {
    // KEYEX_TX: [ver=1][epoch:4][salt:32][srvPub:65][srvNonce:12]
    uint32_t t0 = millis();

    // Max wait: 5s
    Serial.println("Waiting for g_keyexReady");
    while (!g_keyexReady && millis() - t0 < 5000) {
        delay(10);
    }

    if (!g_keyexReady) {
        disconnect();
        Serial.println("[HX] timeout waiting KEYEX_TX notify");
        return false;
    } else {
        Serial.println("KeyEx received");
    }

    const std::string &v = g_keyexPayload;

    if (v.size()!=1+4+32+65+12 || (uint8_t)v[0]!=1) {
        Serial.printf("[HX] bad keyex len=%u\n",(unsigned)v.size());
        return false;
    }
    memcpy(&s_epoch,  &v[1], 4);
    memcpy(s_salt,    &v[1+4], 32);
    memcpy(s_srvPub,  &v[1+4+32], 65);
    memcpy(s_srvNonce,&v[1+4+32+65], 12);

    mbedtls_ecp_group g;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    if(!BLELNBase::ecdh_gen(s_cliPub,g,d,Q)){
        Serial.println("[HX] ecdh_gen fail");
        return false;
    }
    BLELNBase::random_bytes(s_cliNonce,12);

    // [ver=1][cliPub:65][cliNonce:12]
    std::string tx;
    tx.push_back(1);
    tx.append((const char*)s_cliPub,65);
    tx.append((const char*)s_cliNonce,12);


    if(!chKeyExRx->writeValue(tx,true)){
        Serial.println("[HX] write fail");
        return false;
    }

    // ECDH -> shared
    uint8_t ss[32];
    if(!BLELNBase::ecdh_shared(g,d,s_srvPub,ss)){
        Serial.println("[HX] shared fail");
        return false;
    }

    // HKDF salt = salt || epoch(LE)
    uint8_t salt[32+4];
    memcpy(salt,s_salt,32);
    salt[32]=(uint8_t)(s_epoch&0xFF);
    salt[33]=(uint8_t)((s_epoch>>8)&0xFF);
    salt[34]=(uint8_t)((s_epoch>>16)&0xFF);
    salt[35]=(uint8_t)((s_epoch>>24)&0xFF);

    const char infoHdr_s2c[]="BLEv1|sessKey_s2c";
    uint8_t info_s2c[sizeof(infoHdr_s2c) - 1 + 65 + 65 + 12 + 12], *p_s2c=info_s2c;
    memcpy(p_s2c, infoHdr_s2c, sizeof(infoHdr_s2c) - 1);
    p_s2c+= sizeof(infoHdr_s2c) - 1;
    memcpy(p_s2c, s_srvPub, 65); p_s2c+=65;
    memcpy(p_s2c, s_cliPub, 65); p_s2c+=65;
    memcpy(p_s2c, s_srvNonce, 12); p_s2c+=12;
    memcpy(p_s2c, s_cliNonce, 12); p_s2c+=12;
    BLELNBase::hkdf_sha256(salt, sizeof(salt), ss, sizeof(ss), info_s2c, (size_t)(p_s2c - info_s2c), s_sessKey_s2c, 32);

    const char infoHdr_c2s[]="BLEv1|sessKey_c2s";
    uint8_t info_c2s[sizeof(infoHdr_c2s) - 1 + 65 + 65 + 12 + 12], *p_c2s=info_c2s;
    memcpy(p_c2s, infoHdr_c2s, sizeof(infoHdr_c2s) - 1);
    p_c2s+= sizeof(infoHdr_c2s) - 1;
    memcpy(p_c2s, s_srvPub, 65); p_c2s+=65;
    memcpy(p_c2s, s_cliPub, 65); p_c2s+=65;
    memcpy(p_c2s, s_srvNonce, 12); p_c2s+=12;
    memcpy(p_c2s, s_cliNonce, 12); p_c2s+=12;
    BLELNBase::hkdf_sha256(salt, sizeof(salt), ss, sizeof(ss), info_c2s, (size_t)(p_c2s - info_c2s), s_sessKey_c2s, 32);

    uint8_t sidBuf[2];
    const char sidInfo[] = "BLEv1|sid";
    BLELNBase::hkdf_sha256(salt, sizeof(salt),
                ss, sizeof(ss),
                (const uint8_t*)sidInfo, sizeof(sidInfo)-1,
                sidBuf, sizeof(sidBuf));
    s_sid = ((uint16_t)sidBuf[0] << 8) | sidBuf[1];

    s_ctr_s2c=0;
    s_ctr_c2s=0;
    mbedtls_ecp_point_free(&Q); mbedtls_mpi_free(&d); mbedtls_ecp_group_free(&g);

    return true;
}

bool BLELNClient::sendEncrypted(const std::string &msg) {
    const char aadhdr[]="DATAv1";
    uint8_t aad[sizeof(aadhdr)-1+2+4], *a=aad;
    memcpy(a,aadhdr,sizeof(aadhdr)-1); a+=sizeof(aadhdr)-1;
    *a++= (uint8_t)(s_sid>>8);
    *a++= (uint8_t)(s_sid&0xFF);
    *a++= (uint8_t)(s_epoch&0xFF);
    *a++= (uint8_t)((s_epoch>>8)&0xFF);
    *a++= (uint8_t)((s_epoch>>16)&0xFF);
    *a=   (uint8_t)((s_epoch>>24)&0xFF);

    s_ctr_c2s++;
    uint8_t nonce[12];
    BLELNBase::random_bytes(nonce,12);
    std::string ct; uint8_t tag[16];

    if(!BLELNBase::gcm_encrypt(s_sessKey_c2s,(const uint8_t*)msg.data(),msg.size(),nonce,aad,sizeof(aad),ct,tag)){
        Serial.println("[GCM] fail");
        return false;
    }

    std::string pkt;
    pkt.resize(4);
    pkt[0]=(uint8_t)((s_ctr_c2s>>24)&0xFF);
    pkt[1]=(uint8_t)((s_ctr_c2s>>16)&0xFF);
    pkt[2]=(uint8_t)((s_ctr_c2s>>8)&0xFF);
    pkt[3]=(uint8_t)(s_ctr_c2s&0xFF);
    pkt.append((const char*)nonce,12);
    pkt.append(ct);
    pkt.append((const char*)tag,16);

    return chDataRx->writeValue(pkt,false);
}

bool BLELNClient::isConnected() {
    return (client!= nullptr) && (client->isConnected());
}

bool BLELNClient::hasDiscoveredClient() {
    return svc!= nullptr;
}

void BLELNClient::onPassKeyEntry(NimBLEConnInfo &connInfo) {
    g_keyexReady = false;
    NimBLEDevice::injectPassKey(connInfo, 123456);
}

void BLELNClient::onKeyExNotifyClb(__attribute__((unused)) NimBLERemoteCharacteristic *c, uint8_t *pData, size_t length,
                                   __attribute__((unused)) bool isNotify) {
    g_keyexPayload.assign((const char*)pData, length);
    g_keyexReady = true;
}

void BLELNClient::onServerResponse(NimBLERemoteCharacteristic *c, __attribute__((unused)) uint8_t *pData,
                                   __attribute__((unused)) size_t length,
                                   __attribute__((unused)) bool isNotify) {
    const std::string &v = c->getValue();

    if (v.empty()) {
        return;
    }

    appendToQueue(v);
}

bool BLELNClient::isScanning() const {
    return scanning;
}

void BLELNClient::appendToQueue(const std::string &m) {
    auto* heapBuf = (uint8_t*)malloc(m.size());
    if (!heapBuf) return;
    memcpy(heapBuf, m.data(), m.size());

    RxClientPacket pkt{ m.size(), heapBuf };
    if (xQueueSend(g_rxQueue, &pkt, pdMS_TO_TICKS(10)) != pdPASS) {
        free(heapBuf);
    }
}

void BLELNClient::rxWorker() {
    for(;;) {
        if(!runRxWorker){
            if (g_rxQueue) {
                RxClientPacket pkt{};
                while (xQueueReceive(g_rxQueue, &pkt, 0) == pdPASS) {
                    free(pkt.buf);
                }
            }
            return;
        }

        if(s_sid!=0) {
            RxClientPacket pkt{};
            if (xQueueReceive(g_rxQueue, &pkt, pdMS_TO_TICKS(50)) == pdTRUE) {
                if (pkt.len >= 4 + 12 + 16) {
                    const uint8_t *ctrBE = pkt.buf;
                    const uint8_t *nonce = pkt.buf + 4;
                    const uint8_t *ct = pkt.buf + 4 + 12;
                    size_t ctLen = pkt.len - (4 + 12 + 16);
                    const uint8_t *tag = pkt.buf + (pkt.len - 16);

                    uint32_t ctr = (uint32_t) ctrBE[0] << 24 | (uint32_t) ctrBE[1] << 16 |
                                   (uint32_t) ctrBE[2] << 8 | (uint32_t) ctrBE[3];
                    if (ctr > s_ctr_s2c) {
                        // AAD: "DATAv1"|sid(BE)|epoch(LE)
                        const char aadhdr[] = "DATAv1";
                        uint8_t aad[sizeof(aadhdr) - 1 + 2 + 4], *a = aad;
                        memcpy(a, aadhdr, sizeof(aadhdr) - 1);
                        a += sizeof(aadhdr) - 1;
                        *a++ = (uint8_t)(s_sid >> 8);
                        *a++ = (uint8_t)(s_sid & 0xFF);
                        *a++ = (uint8_t)(s_epoch & 0xFF);
                        *a++ = (uint8_t)((s_epoch >> 8) & 0xFF);
                        *a++ = (uint8_t)((s_epoch >> 16) & 0xFF);
                        *a = (uint8_t)((s_epoch >> 24) & 0xFF);

                        mbedtls_gcm_context g;
                        mbedtls_gcm_init(&g);
                        if (mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, s_sessKey_s2c, 256) != 0) {
                            mbedtls_gcm_free(&g);
                        } else {
                            std::string plain;
                            plain.resize(ctLen);
                            int rc = mbedtls_gcm_auth_decrypt(&g, ctLen, nonce, 12, aad, sizeof(aad),
                                                              tag, 16, ct, (uint8_t *) plain.data());
                            mbedtls_gcm_free(&g);
                            if (rc == 0) {
                                s_ctr_s2c = ctr;

                                if (onMsgRx) {
                                    onMsgRx(plain);
                                }
                            }
                        }
                    }
                }

                free(pkt.buf);
            }

            if (uxQueueMessagesWaiting(g_rxQueue) > 0) {
                vTaskDelay(pdMS_TO_TICKS(1));
            } else {
                vTaskDelay(pdMS_TO_TICKS(50));
            }
        } else {
            vTaskDelay(pdMS_TO_TICKS(50));
        }
    }
}

void BLELNClient::onDisconnect(NimBLEClient *pClient, int reason) {
    NimBLEClientCallbacks::onDisconnect(pClient, reason);
}

void BLELNClient::onConnect(NimBLEClient *pClient) {
    if(onConRes){
        onConRes(true, 0);
    }
    Serial.println("Client connected");
}

void BLELNClient::onConnectFail(NimBLEClient *pClient, int reason) {
    if(onConRes)
        onConRes(false, reason);
}


void BLELNClient::disconnect() {
    chKeyExTx->unsubscribe();
    chDataTx->unsubscribe();

    svc= nullptr;
    chKeyExTx = nullptr;
    chKeyExRx = nullptr;
    chDataTx  = nullptr;
    chDataRx  = nullptr;

    client->disconnect();
    NimBLEDevice::deleteClient(client);

    s_sid = 0;
    s_ctr_s2c = 0;
    s_ctr_c2s = 0;
    memset(s_sessKey_s2c, 0, sizeof(s_sessKey_s2c));
    memset(s_sessKey_c2s, 0, sizeof(s_sessKey_c2s));
    memset(s_cliPub, 0, sizeof(s_cliPub));
    memset(s_srvPub, 0, sizeof(s_srvPub));
    memset(s_cliNonce, 0, sizeof(s_cliNonce));
    memset(s_srvNonce, 0, sizeof(s_srvNonce));
    memset(s_salt, 0, sizeof(s_salt));
    s_epoch = 0;
    g_keyexPayload.clear();
    g_keyexReady = false;
}



