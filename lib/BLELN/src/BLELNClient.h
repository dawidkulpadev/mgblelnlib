//
// Created by dkulpa on 17.08.2025.
//

#ifndef MGLIGHTFW_G2_BLELNCLIENT_H
#define MGLIGHTFW_G2_BLELNCLIENT_H

#include "BLELNBase.h"
#include <NimBLEDevice.h>

struct RxClientPacket {
    size_t   len;
    uint8_t* buf;    // malloc/free
};

class BLELNClient : public NimBLEScanCallbacks, public NimBLEClientCallbacks{
public:
    void start(const std::string &name, std::function<void(std::string)> onServerResponse);
    void stop();
    void startServerSearch(uint32_t durationMs, const std::string &serverUUID, const std::function<void(const NimBLEAdvertisedDevice *advertisedDevice)>& onResult);
    void beginConnect(const NimBLEAdvertisedDevice *advertisedDevice);
    bool sendEncrypted(const std::string& msg);

    bool isScanning() const;
    bool isConnected();
    bool hasDiscoveredClient();

    void onConnect(NimBLEClient* pClient) override;
    void onDiscovered(const NimBLEAdvertisedDevice* advertisedDevice) override;
    void onResult(const NimBLEAdvertisedDevice* advertisedDevice) override;
    void onScanEnd(const NimBLEScanResults& scanResults, int reason) override;
    void onDisconnect(NimBLEClient* pClient, int reason) override;

    void rxWorker();
    void appendToQueue(const std::string &m);

    void onPassKeyEntry(NimBLEConnInfo& connInfo) override;

    bool discover();
    bool handshake();

private:
    void onKeyExNotifyClb(__attribute__((unused)) NimBLERemoteCharacteristic* pBLERemoteCharacteristic, uint8_t* pData, size_t length,
                          __attribute__((unused)) bool isNotify);
    void onServerResponse(NimBLERemoteCharacteristic* pBLERemoteCharacteristic, __attribute__((unused)) uint8_t* pData,
                          __attribute__((unused)) size_t length, __attribute__((unused)) bool isNotify);

    NimBLEClient* client=nullptr;
    NimBLERemoteService* svc=nullptr;
    NimBLERemoteCharacteristic *chKeyExTx=nullptr,*chKeyExRx=nullptr,*chDataTx=nullptr,*chDataRx=nullptr;

    bool scanning = false;
    std::function<void(const NimBLEAdvertisedDevice *advertisedDevice)> onScanResult;
    std::string searchedUUID;

    std::function<void(std::string)> onMsgRx;
    bool runRxWorker=false;

    QueueHandle_t g_rxQueue;

    volatile bool g_keyexReady = false;
    std::string   g_keyexPayload;

    volatile uint16_t s_sid=0;
    uint32_t s_epoch=0;
    uint8_t  s_salt[32];
    uint8_t  s_srvPub[65], s_srvNonce[12];
    uint8_t  s_cliPub[65], s_cliNonce[12];
    uint8_t  s_sessKey_c2s[32], s_sessKey_s2c[32];
    uint32_t s_ctr_c2s=0, s_ctr_s2c=0;


};


#endif //MGLIGHTFW_G2_BLELNCLIENT_H
