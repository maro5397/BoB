#include "dot11.h"
#include <iostream>

bool Dot11BeaconFrame::checkBeaconType()
{
    u_int8_t typedata = framecontrol_;
    if(typedata >> 4 == 0b1000 && ((typedata >> 2) & 0b000011) == 0b00)
        return true;
    return false;
}

void Dot11PacketForm::setTagTree(const u_char* pk, int len)
{
    int point = 0;
    while(point != len)
    {
        TaggedParameter item;
        item.tagnum_ = *(pk+point+0);
        item.taglen_ = *(pk+point+1);
        item.data_ = pk+point+2;
        taggedps_.insert({*(pk+point+0), item});
        point += *(pk+point+1)+2;
    }
    return;
}

int Dot11PacketForm::addBssidInMap(Mac bssid, std::pair<std::string, std::pair<int, int>> value)
{
    beaconbssid.insert({bssid, value}); //if there is bssid already it didn't insert
    auto item = beaconbssid.find(bssid);
    item->second.second.first++;
    item->second.second.second = value.second.second;
    return item->second.second.first;
}

void Dot11PacketForm::printPacketData()
{
    system("clear");
    printf("=====================================================\n");
    for(auto beacondata : beaconbssid)
    {
        std::cout << "PWR: " << beacondata.second.second.second << std::endl;
        std::cout << "BSSID: " << std::string(beacondata.first) << std::endl;
        std::cout << "ESSID: " << std::string(beacondata.second.first) << std::endl;
        std::cout << "Beacons: " << beacondata.second.second.first << std::endl;
        printf("=====================================================\n");
    }
}