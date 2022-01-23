#pragma once
#include <stdint.h>
#include <map>
#include "mac.h"

typedef uint8_t  u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
typedef uint64_t u_int64_t;

#ifndef RADIOTAPHDR_LEN     
#define RADIOTAPHDR_LEN 0x18 //24byte
#endif

#ifndef DOT11BEACONFRAME_LEN   
#define DOT11BEACONFRAME_LEN    0x18 //24byte
#endif

#ifndef DOT11WIRELESSMANFIXED_LEN  
#define DOT11WIRELESSMANFIXED_LEN   0xc //12byte
#endif

#ifndef DOT11BEFORETP_LEN  
#define DOT11BEFORETP_LEN   0x3c //60byte
#endif

struct Dot11RadioTapHdr
{
    u_int8_t revision_;
    u_int8_t pad_;
    u_int16_t len_;
    u_int32_t frontpresentflag_;
    u_int32_t backpresentflag_;
    u_int8_t flag_;
    u_int8_t datarate_;
    u_int16_t channelfre_;
    u_int16_t channelflag_;
    u_int8_t frontantennasignal_; //PWR
    u_int8_t padding_;
    u_int16_t rxflag_;
    u_int8_t backantennasignal_;
    u_int8_t antenna_;
};

struct Dot11BeaconFrame
{
    u_int8_t framecontrol_;
    u_int8_t flags_;
    u_int16_t duration_;
    u_int8_t desmac_[6];
    u_int8_t srcmac_[6];
    u_int8_t bssidmac_[6]; //bss
    u_int16_t fragseqnum_;

    bool checkBeaconType();
};

struct FixedParameters
{
    u_int64_t timestamp_;
    u_int16_t beaconinterval_;
    u_int16_t capabilitiesinfo_;
};

struct TaggedParameter //ess
{
    u_int8_t tagnum_;
    u_int8_t taglen_;
    const unsigned char* data_;
};

struct Dot11PacketForm
{
    Dot11RadioTapHdr dot11rth_;
    Dot11BeaconFrame dot11bf_;
    FixedParameters fixedp_;
    const unsigned char* taggedp_;

    std::map<u_int8_t, TaggedParameter> taggedps_;

    std::map<Mac, std::pair<std::string, std::pair<int, int>>> beaconbssid;

    void setTagTree(const u_char* pk, int len);
    int addBssidInMap(Mac bssid, std::pair<std::string, std::pair<int, int>> value);
    void printPacketData();
};