#include "dot11.h"
#include <iostream>

bool Dot11BeaconFrame::checkBeaconType()
{
    u_int8_t typedata = framecontrol_;
    if(typedata >> 4 == 0b1000 && ((typedata >> 2) & 0b000011) == 0b00)
        return true;
    return false;
}

bool TaggedParameter::nextData()
{
    if((pointer_-starter_)/sizeof(u_int8_t*) == entirelen_)
        return false;
    pointer_ = pointer_ + taglen_ + sizeof(tagnum_) + sizeof(taglen_);
    return true;
}

int BeaconPacketForm::addBssidInMap(Mac bssid, std::pair<std::string, int> value)
{
    beaconbssid.insert({bssid, value}); //if there is bssid already it didn't insert
    auto item = beaconbssid.find(bssid);
    item->second.second++;
    return item->second.second;
}

void BeaconPacketForm::printPacketData()
{
    system("clear");
    printf("=====================================================\n");
    for(auto beacondata : beaconbssid)
    {
        std::cout << "BSSID: " << std::string(beacondata.first) << std::endl;
        std::cout << "ESSID: " << std::string(beacondata.second.first) << std::endl;
        std::cout << "Beacons: " << beacondata.second.second << std::endl;
        printf("=====================================================\n");
    }
}

bool TaggedParameter::parse()
{
    if((pointer_-starter_)/sizeof(u_int8_t*) == entirelen_)
        return false;
    tagnum_ = *(pointer_+0);
    taglen_ = *(pointer_+1);
    data_ = pointer_+2;
    return true;
}

void TaggedParameter::setting(const unsigned char* pointer, int len)
{
    starter_ = pointer;
    pointer_ = pointer;
    entirelen_ = len;
}