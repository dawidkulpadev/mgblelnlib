//
// Created by dkulpa on 17.08.2025.
//

#ifndef MGLIGHTFW_G2_BLELNSERVER_H
#define MGLIGHTFW_G2_BLELNSERVER_H

#include "Arduino.h"
#include "BLELNConnCtx.h"
#include "BLELNBase.h"
#include <NimBLEDevice.h>
#include <Preferences.h>

#include <mbedtls/gcm.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h> // HMAC (HKDF implementujemy ręcznie)

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/queue.h>

#define ROTATE_MS (24ul * 60ul * 60ul * 1000ul)

struct RxPacket {
    uint16_t conn;
    size_t   len;
    uint8_t* buf;    // malloc/free
};

class BLELNServer : public NimBLEScanCallbacks, public NimBLEServerCallbacks{
public:
    // User methods
    void start(Preferences *prefs, const std::string &name, const std::string &uuid);
    void stop();

    void startOtherServerSearch(uint32_t durationMs, const std::string &therUUID, const std::function<void(bool)>& onResult);

    bool getConnContext(uint16_t h, BLELNConnCtx** c);

    void setChDataTx(const std::string &s);
    void notifyChDataTx();
    void maybe_rotate(Preferences *prefs);


    bool noClientsConnected();

    void appendToQueue(uint16_t h, const std::string &m);
    void rxWorker();
    bool sendEncrypted(BLELNConnCtx *cx, const std::string& msg);
    bool sendEncrypted(uint16_t h, const std::string& msg);
    bool sendEncrypted(const std::string& msg);

    void setOnMessageReceivedCallback(std::function<void(uint16_t cliH, const std::string& msg)> cb);

private:
    std::function<void(uint16_t cliH, const std::string& msg)> onMsgReceived;

    std::string serviceUUID;

    // NimBLE
    NimBLEServer* srv = nullptr;
    NimBLECharacteristic *chKeyExTx=nullptr, *chKeyExRx=nullptr, *chDataTx=nullptr, *chDataRx=nullptr;

    // Multithreading
    SemaphoreHandle_t clisMtx = nullptr;
    SemaphoreHandle_t keyExTxMtx = nullptr;
    SemaphoreHandle_t txMtx = nullptr;
    QueueHandle_t g_rxQueue;

    // Encryption
    uint8_t g_psk_salt[32];
    uint32_t g_epoch = 0;
    uint32_t g_lastRotateMs = 0;

    // BLELN
    std::vector<BLELNConnCtx> connCtxs;
    bool runRxWorker=false;

    bool scanning = false;
    std::function<void(bool found)> onScanResult;
    std::string searchedUUID;

    // Private methods
    bool sendEncrypted(int i, const std::string& msg);
    void sendKeyToClient(BLELNConnCtx *cx);

    // Callbacks
    void onResult(const NimBLEAdvertisedDevice* advertisedDevice) override;
    void onScanEnd(const NimBLEScanResults& scanResults, int reason) override;
    void onConnect(NimBLEServer* pServer, NimBLEConnInfo& connInfo) override;
    void onDisconnect(NimBLEServer* pServer, NimBLEConnInfo& connInfo, int reason) override;
    void onDataWrite(NimBLECharacteristic* c, NimBLEConnInfo& info);
    void onKeyExRxWrite(NimBLECharacteristic* c, NimBLEConnInfo& info);
    void onKeyExTxSubscribe(NimBLECharacteristic *pCharacteristic, NimBLEConnInfo &connInfo, uint16_t subValue);

    // Callback classes
    class DataRxClb : public NimBLECharacteristicCallbacks{
    public:
        explicit DataRxClb(BLELNServer *parent): parentServer(parent){}
    private:
        BLELNServer *parentServer;
        void onWrite(NimBLECharacteristic* c, NimBLEConnInfo& info) override{
            parentServer->onDataWrite(c, info);
        }
    };

    class KeyExRxClb : public NimBLECharacteristicCallbacks {
    public:
        explicit KeyExRxClb(BLELNServer *parent): parentServer(parent){}
    private:
        BLELNServer *parentServer;
        void onWrite(NimBLECharacteristic* c, NimBLEConnInfo& info) override{
            parentServer->onKeyExRxWrite(c, info);
        }
    };

    class KeyExTxClb : public NimBLECharacteristicCallbacks {
    public:
        explicit KeyExTxClb(BLELNServer *parent): parentServer(parent){}
    private:
        BLELNServer *parentServer;
        void onSubscribe(NimBLECharacteristic *pCharacteristic, NimBLEConnInfo &connInfo, uint16_t subValue) override{
            parentServer->onKeyExTxSubscribe(pCharacteristic, connInfo, subValue);
        }
    };
};


#endif //MGLIGHTFW_G2_BLELNSERVER_H
