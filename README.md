# Counter-Strike 2 Anticheat

Anticheat measures found in the binaries of Counter-Strike 2.
The analysis is based on the very first beta release.

## VMT pointer check of global interfaces

```cpp
// 48 89 4C 24 ? 48 81 EC ? ? ? ? 48 8D 4C 24 @ client.dll
void collectInterfacesData(CUserMessage_Inventory_Response& protobuf);
```

This function iterates over `g_pInterfaceGlobals` array (name from Source 1 engine) and for every interface fills `InventoryDetail` protobuf:

```text
message InventoryDetail {
    optional int32 index = 1; // index in the g_pInterfaceGlobals array
    optional int64 primary = 2; // *g_pInterfaceGlobals[index] (address of the interface)
    optional int64 offset = 3; // **g_pInterfaceGlobals[index] (address of virtual method table of the interface)
    optional int64 first = 4; // address of the first function in the VMT
    optional int64 base = 5;
    optional string name = 6;
    optional string base_name = 7;
    optional int32 base_detail = 8;
    optional int32 base_time = 9;
    optional int32 base_hash = 10; // interface name hash
}
(fields without a comment are unused)
```

## Integrity of read-only sections of game DLLs

This check is present in `client.dll` under the name "ComputeInventory2".
Game DLLs register themselves by calling `Plat_RegisterModule(moduleHandle)` function from `tier0.dll`. The list of registered modules can be retrieved by calling `Plat_GetRegisteredModules()`.

When game server sends [CUserMessageRequestInventory](https://github.com/SteamDatabase/GameTracking-CSGO/blob/49680faef0fbccdead5803e3d559e6a36372ac8f/Protobufs/usermessages.proto#L631-L635) protobuf message to the client, the client responds with [CUserMessage_Inventory_Response](https://github.com/SteamDatabase/GameTracking-CSGO/blob/49680faef0fbccdead5803e3d559e6a36372ac8f/Protobufs/usermessages.proto#L637-L662) message containing info about registered modules.

For every registered dll:

```cpp
struct DllSectionsResult {
    void* baseOfDll;
    IMAGE_NT_HEADERS* ntHeaders;
    void* buffer; // allocated with VirtualAlloc in processDllSections()
    DWORD timestamp; // from IMAGE_FILE_HEADER::TimeDateStamp
    DWORD pad; // padding
    CSHA1 sha1; // sizeof(CSHA1) == 192, seems not to be computed currently
    CRC32 readOnlySectionsHash;
};

// E8 ? ? ? ? 8B 8C 24 ? ? ? ? 0F B6 D8 (relative jump) @ client.dll
bool processDllSections(DllSectionsResult& output, HMODULE dll);
```

processDllSections() allocates the buffer of size `IMAGE_OPTIONAL_HEADER::SizeOfImage` and does the following:

- copies the headers to the buffer (`IMAGE_OPTIONAL_HEADER::SizeOfHeaders` bytes at dll base)
- copies every unwritable section (`(IMAGE_SECTION_HEADER::Characteristics & IMAGE_SCN_MEM_WRITE) == 0`) to the buffer
- iterates over base relocation table (`IMAGE_DIRECTORY_ENTRY_BASERELOC`) and undoes relocations in the buffer (only `IMAGE_REL_BASED_DIR64` relocations)
- zeroes import address table (`IMAGE_DIRECTORY_ENTRY_IAT`) and export directory (`IMAGE_DIRECTORY_ENTRY_EXPORT`) in the buffer
- computes CRC32 of read-only sections in the buffer

processDllSections() is called by another function:

```cpp
// E8 ? ? ? ? 0F B6 C0 85 C0 74 7B (relative jump) @ client.dll
bool processDll(
    HMODULE dll,
    CRC32& readOnlySectionsHash,
    char* pdbPath,
    DWORD& sizeOfImage,
    DWORD& timestamp,
    void** imageBase
);
```

processDll() does the following:

- calls processDllSections() and copies the fields of returned DllSectionsResult to the output parameters
- copies PDB path from debug directory to `pdbPath` output buffer

Later PDB file name is extracted from path and hashed.

[InventoryDetail](https://github.com/SteamDatabase/GameTracking-CSGO/blob/49680faef0fbccdead5803e3d559e6a36372ac8f/Protobufs/usermessages.proto#L638-L649) protobuf is filled with the gathered info.

```text
message InventoryDetail {
    optional int32 index = 1; // index in the array of registered modules
    optional int64 primary = 2; // image base from IMAGE_OPTIONAL_HEADER
    optional int64 offset = 3; // size of image
    optional int64 first = 4;
    optional int64 base = 5; // dll handle
    optional string name = 6;
    optional string base_name = 7;
    optional int32 base_detail = 8; // crc32 of read-only sections
    optional int32 base_time = 9; // timestamp from IMAGE_FILE_HEADER
    optional int32 base_hash = 10; // PDB filename hash
}
(fields without a comment are unused)
```
