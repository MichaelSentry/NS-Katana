<?php 
namespace NinjaSentry\Katana\Firewall\Access;

final class Group
{
    const BANNED         = 1;
    const INTRUSION      = 2;
    const PARASITE       = 4;
    const SE_FRAUD       = 8;
    const ROBOT          = 16
    const PROXY          = 32;
    CONST SEARCH_ENGINE  = 64;
    CONST GUEST          = 128;
    CONST ADMIN          = 256;
}
