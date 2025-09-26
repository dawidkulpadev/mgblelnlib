//
// Created by dkulpa on 17.08.2025.
//

#include "BLELNServer.h"

#include <utility>
#include "BLELNBase.h"


void BLELNServer::onConnect(NimBLEServer *pServer, NimBLEConnInfo &connInfo) {
    BLELNConnCtx* c = nullptr;

    if(!getConnContext(connInfo.getConnHandle(), &c)){
        Serial.println("Failed searching for context!");
        return;
    }

    if (c == nullptr) {
        Serial.println("Creating new ConnCtx");
        if(xSemaphoreTake(clisMtx, pdMS_TO_TICKS(100))!=pdTRUE){
            Serial.println("Failed locking semaphore! (create new client)!");
            return;
        }
        connCtxs.emplace_back(connInfo.getConnHandle());
        c = (connCtxs.end()-1).base();
        xSemaphoreGive(clisMtx);
        Serial.println(("New client handle: "+std::to_string(c->getHandle())).c_str());
    }
    if (!c->getEncData()->makeServerKeys(&BLELNBase::ctr_drbg)) {
        Serial.println("ECDH keygen fail");
        return;
    }


    NimBLEDevice::startAdvertising();
}

void BLELNServer::onDisconnect(NimBLEServer *pServer, NimBLEConnInfo &connInfo, int reason) {
    int removeIdx = -1;

    if(xSemaphoreTake(clisMtx, pdMS_TO_TICKS(100))!=pdTRUE){
        Serial.println("Failed locking semaphore! (onDisconnect)");
        return;
    }
    for (int i=0; i<connCtxs.size(); i++){
        if (connCtxs[i].getHandle() == connInfo.getConnHandle()){
            removeIdx = i;
            break;
        }
    }
    if(removeIdx>=0){
        connCtxs.erase(connCtxs.begin()+removeIdx);
    }
    xSemaphoreGive(clisMtx);
    NimBLEDevice::startAdvertising();
}

void BLELNServer::start(Preferences *prefs, const std::string &name, const std::string &uuid) {
    serviceUUID= uuid;

    clisMtx= xSemaphoreCreateMutex();
    keyExTxMtx = xSemaphoreCreateMutex();
    txMtx = xSemaphoreCreateMutex();
    g_rxQueue = xQueueCreate(20, sizeof(RxPacket));

    runRxWorker= true;
    xTaskCreatePinnedToCore(
            [](void* arg){
                static_cast<BLELNServer*>(arg)->rxWorker();
                Serial.println("BLELN Server: rx worker stopped");
                vTaskDelete(nullptr);
            },
            "BLELNrx", 2560, this, 5, nullptr, 1);

    BLELNBase::load_or_init_psk(prefs, g_psk_salt, &g_epoch);
    BLELNBase::rng_init();

    NimBLEDevice::init(name);
    NimBLEDevice::setMTU(247);

    // Security: bonding + MITM + LE Secure Connections
    NimBLEDevice::setSecurityAuth(false, false, false);

    srv = NimBLEDevice::createServer();
    srv->setCallbacks(this);

    auto* svc = srv->createService(serviceUUID);

    chKeyExTx = svc->createCharacteristic(BLELNBase::KEYEX_TX_UUID, NIMBLE_PROPERTY::NOTIFY);
    chKeyExRx = svc->createCharacteristic(BLELNBase::KEYEX_RX_UUID, NIMBLE_PROPERTY::WRITE);// | NIMBLE_PROPERTY::WRITE_ENC | NIMBLE_PROPERTY::WRITE_AUTHEN);
    chDataTx  = svc->createCharacteristic(BLELNBase::DATA_TX_UUID,  NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::NOTIFY);// | NIMBLE_PROPERTY::READ_ENC);
    chDataRx  = svc->createCharacteristic(BLELNBase::DATA_RX_UUID,  NIMBLE_PROPERTY::WRITE);// | NIMBLE_PROPERTY::WRITE_ENC | NIMBLE_PROPERTY::WRITE_AUTHEN);

    chKeyExTx->setCallbacks(new KeyExTxClb(this));
    chKeyExRx->setCallbacks(new KeyExRxClb(this));
    chDataRx->setCallbacks(new DataRxClb(this));

    svc->start();

    auto* adv = NimBLEDevice::getAdvertising();
    adv->setName(name);
    adv->addServiceUUID(serviceUUID);
    adv->enableScanResponse(true);

    NimBLEDevice::startAdvertising();

    g_lastRotateMs = millis();
}


bool BLELNServer::getConnContext(uint16_t h, BLELNConnCtx** ctx) {
    *ctx = nullptr;

    if(xSemaphoreTake(clisMtx, pdMS_TO_TICKS(100))!=pdTRUE) return false;
    for (auto &c : connCtxs){
        if (c.getHandle() == h){
            *ctx = &c;
            break;
        }
    }
    xSemaphoreGive(clisMtx);

    return true;
}

void BLELNServer::setChDataTx(const std::string &s) {
    chDataTx->setValue(s.c_str());
}

void BLELNServer::notifyChDataTx() {
    chDataTx->notify();
}

void BLELNServer::maybe_rotate(Preferences *prefs) {
    uint32_t now = millis();
    if (now - g_lastRotateMs >= ROTATE_MS) {
        BLELNBase::rotate_psk(prefs, g_psk_salt, &g_epoch);
        g_lastRotateMs = now;
    }
}

void BLELNServer::sendKeyToClient(BLELNConnCtx *cx) {
    // KEYEX_TX: [ver=1][epoch:4B][salt:32B][srvPub:65B][srvNonce:12B]
    std::string keyex;
    keyex.push_back(1);
    keyex.append((const char*)&g_epoch, 4); // LE
    keyex.append((const char*)g_psk_salt, 32);
    keyex.append(cx->getEncData()->getPublicKeyString());
    keyex.append(cx->getEncData()->getNonceString());

    if(xSemaphoreTake(keyExTxMtx, pdMS_TO_TICKS(100)) == pdTRUE) {
        chKeyExTx->setValue(keyex);
        chKeyExTx->notify(cx->getHandle());
        cx->setKeySent(true);
        xSemaphoreGive(keyExTxMtx);
    } else {
        Serial.println("Failed locking semaphore! (Key Exchange)");
    }
}

void BLELNServer::appendToQueue(uint16_t h, const std::string &m) {
    auto* heapBuf = (uint8_t*)malloc(m.size());
    if (!heapBuf) return;
    memcpy(heapBuf, m.data(), m.size());

    RxPacket pkt{ h, m.size(), heapBuf };
    if (xQueueSend(g_rxQueue, &pkt, pdMS_TO_TICKS(10)) != pdPASS) {
        free(heapBuf);
    }
}

void BLELNServer::rxWorker() {
   for(;;) {
        if(!runRxWorker){
            if (g_rxQueue) {
                RxPacket pkt{};
                while (xQueueReceive(g_rxQueue, &pkt, 0) == pdPASS) {
                    free(pkt.buf);
                }
            }
            return;
        }

        RxPacket pkt{};
        if (xQueueReceive(g_rxQueue, &pkt, 0) == pdTRUE) {
            BLELNConnCtx *cx;
            if(getConnContext(pkt.conn, &cx) and (cx!= nullptr)) {
                std::string v(reinterpret_cast<char*>(pkt.buf), pkt.len);

                std::string plain;
                if (cx->getEncData()->decryptAESGCM((const uint8_t *) v.data(), v.size(), plain)) {
                    if (plain.size() > 200) plain.resize(200);
                    for (auto &ch: plain) if (ch == '\0') ch = ' ';

                    if(onMsgReceived)
                        onMsgReceived(cx->getHandle(), plain);
                } else {
                    // TODO: Inform error
                }

                free(pkt.buf);
            }
        }

        if(uxQueueMessagesWaiting(g_rxQueue)>0){
            vTaskDelay(pdMS_TO_TICKS(1));
        } else {
            vTaskDelay(pdMS_TO_TICKS(50));
        }
    }
}

bool BLELNServer::sendEncrypted(BLELNConnCtx *cx, const std::string &msg) {
    std::string encrypted;
    if(!cx->getEncData()->encryptAESGCM(msg, encrypted)){
        Serial.println("Encrypt failed");
        return false;
    }

    chDataTx->setValue(encrypted);
    chDataTx->notify(cx->getHandle());
    return true;
}

void BLELNServer::onDataWrite(NimBLECharacteristic *c, NimBLEConnInfo &info) {
    BLELNConnCtx *cx;
    if(!getConnContext(info.getConnHandle(), &cx)){
        Serial.println("Failed locking semaphore! (onWrite)");
        return;
    }
    if (!cx) {
        Serial.println("Received message from unknown client");
        return;
    }
    const std::string &v = c->getValue();

    if (v.empty()) {
        return;
    }

    appendToQueue(info.getConnHandle(), v);
}

void BLELNServer::onKeyExRxWrite(NimBLECharacteristic *c, NimBLEConnInfo &info) {
    Serial.println("Received keyRX");
    BLELNConnCtx *cx;
    if(!getConnContext(info.getConnHandle(), &cx)){
        return;
    }
    if (!cx) return;

    const std::string &v = c->getValue();
    // [ver=1][cliPub:65][cliNonce:12]
    if (v.size()!=1+65+12 || (uint8_t)v[0]!=1) { Serial.println("[HX] bad packet"); return; }

    bool r= cx->getEncData()->deriveSessionKey(&BLELNBase::ctr_drbg, (const uint8_t*)&v[1],
                                               (const uint8_t*)&v[1+65], g_psk_salt,
                                               g_epoch);

    if (!r ) {
        Serial.println("[HX] derive failed"); return;
    }
    cx->setSessionReady(true);
    sendEncrypted(cx, "$HDSH,OK");
}

void BLELNServer::onKeyExTxSubscribe(NimBLECharacteristic *pCharacteristic, NimBLEConnInfo &connInfo, uint16_t subValue) {
    Serial.println("Client subscribed for KeyTX");
    BLELNConnCtx *cx;
    if(!getConnContext(connInfo.getConnHandle(), &cx) or (cx== nullptr)) return;

    if(cx->isSendKeyNeeded()){
        sendKeyToClient(cx);
    }
}

bool BLELNServer::sendEncrypted(int i, const std::string &msg) {
    if(xSemaphoreTake(clisMtx, pdMS_TO_TICKS(100))!=pdTRUE) return false;

    if(i<connCtxs.size()){
        sendEncrypted(&connCtxs[i], msg);
    }
    xSemaphoreGive(clisMtx);

    return true;
}

bool BLELNServer::sendEncrypted(const std::string &msg) {
    for(int i=0; i<connCtxs.size(); i++){
        if(!sendEncrypted(i, msg)) return false;
    }

    return true;
}

void BLELNServer::stop() {
    NimBLEDevice::stopAdvertising();
    // Stop rx worker
    runRxWorker= false;

    if(g_rxQueue)
        xQueueReset(g_rxQueue);

    // Disconnect every client
    if (srv!=nullptr) {
        if(xSemaphoreTake(clisMtx, pdMS_TO_TICKS(300))==pdTRUE) {
            for (auto &c: connCtxs) {
                srv->disconnect(c.getHandle());
            }
            xSemaphoreGive(clisMtx);
        }
    }

    // Remove callbacks
    if (chKeyExTx)
        chKeyExTx->setCallbacks(nullptr);
    if (chKeyExRx)
        chKeyExRx->setCallbacks(nullptr);
    if (chDataRx)
        chDataRx ->setCallbacks(nullptr);

    // Clear semaphores
    if(clisMtx){
        vSemaphoreDelete(clisMtx);
        clisMtx = nullptr;
    }
    if(keyExTxMtx){
        vSemaphoreDelete(keyExTxMtx);
        keyExTxMtx = nullptr;
    }
    if(txMtx){
        vSemaphoreDelete(txMtx);
        txMtx = nullptr;
    }

    // Clear context list
    connCtxs.clear();

    // Reset pointer and callback
    chKeyExTx = nullptr;
    chKeyExRx = nullptr;
    chDataTx  = nullptr;
    chDataRx  = nullptr;
    srv       = nullptr;
    onMsgReceived = nullptr;

    NimBLEDevice::deinit(true);
}

void BLELNServer::setOnMessageReceivedCallback(std::function<void(uint16_t cliH, const std::string& msg)> cb) {
    onMsgReceived= std::move(cb);
}

bool BLELNServer::sendEncrypted(uint16_t h, const std::string &msg) {
    BLELNConnCtx *connCtx= nullptr;
    getConnContext(h, &connCtx);

    if(connCtx!= nullptr) {
        if (xSemaphoreTake(clisMtx, pdMS_TO_TICKS(100)) != pdTRUE) return false;
        sendEncrypted(connCtx, msg);
        xSemaphoreGive(clisMtx);
        return true;
    }

    return false;
}

void BLELNServer::startOtherServerSearch(uint32_t durationMs, const std::string &otherUUID, const std::function<void(bool)>& onResult) {
    scanning = true;
    onScanResult= onResult;
    searchedUUID= otherUUID;
    auto* scan=NimBLEDevice::getScan();
    scan->setScanCallbacks(this, false);
    scan->setActiveScan(true);
    scan->start(durationMs, false, false);
}

void BLELNServer::onResult(const NimBLEAdvertisedDevice *advertisedDevice) {
    if (advertisedDevice->isAdvertisingService(NimBLEUUID(searchedUUID))) {
        scanning = false;
        if(onScanResult){
            onScanResult(true);
        }
    }
}

void BLELNServer::onScanEnd(const NimBLEScanResults &scanResults, int reason) {
    scanning = false;
    if(onScanResult){
        onScanResult(false);
    }
}

bool BLELNServer::noClientsConnected() {
    uint8_t clisCnt=1;

    if(xSemaphoreTake(clisMtx, pdMS_TO_TICKS(50))==pdTRUE){
        clisCnt= connCtxs.size();
        xSemaphoreGive(clisMtx);
    }

    return clisCnt==0;
}

