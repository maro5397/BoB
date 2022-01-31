#pragma once
#include <stdint.h>
#include <map>
#include "mac.h"

typedef uint8_t  u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
typedef uint64_t u_int64_t;

#ifndef RADIOTAPHDR_LEN     
#define RADIOTAPHDR_LEN 0x8 //8byte
#endif

#ifndef DOT11BEACONFRAME_LEN   
#define DOT11BEACONFRAME_LEN    0x18 //24byte
#endif

#ifndef DOT11WIRELESSMANFIXED_LEN  
#define DOT11WIRELESSMANFIXED_LEN   0xc //12byte
#endif

struct Dot11RadioTapHdr
{
    u_int8_t revision_;
    u_int8_t pad_;
    u_int16_t len_; //2byte skip
    u_int32_t presentflag_;
    //jump len_
};

struct Dot11BeaconFrame
{
    u_int8_t framecontrol_;
    u_int8_t flags_;
    u_int16_t duration_;
    Mac addr1_; //destination mac
    Mac addr2_; //transmitter mac
    Mac addr3_; //bssid
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
    const unsigned char* starter_;
    const unsigned char* pointer_;

    u_int8_t tagnum_;
    u_int8_t taglen_;
    const unsigned char* data_;

    int entirelen_;

    void setting(const unsigned char* pointer, int len);
    bool parse();
    bool nextData();
};

struct BeaconPacketForm
{
    Dot11BeaconFrame dot11bf_;
    FixedParameters fixedp_;
    TaggedParameter taggedp_;

    std::map<Mac, std::pair<std::string, int>> beaconbssid;

    int addBssidInMap(Mac bssid, std::pair<std::string, int> value);
    void printPacketData();
};