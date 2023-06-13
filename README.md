# Counter-Strike 2 Anticheat

Anticheat measures found in the binaries of Counter-Strike 2.
The analysis is based on the 6 June 2023 update.

## What's new

### 6 June 2023

- new functionality added to CUserMessage_Inventory_Response to collect something from entity system
- new CUserMessageRequestDiagnostic / CUserMessage_Diagnostic_Response to detect debuggers

## Detections which use protobufs

| Request proto | Response proto | What is does |
| --- | --- | --- |
| CUserMessageRequestDllStatus | CUserMessage_DllStatus | Trusted Mode |
| CUserMessageRequestUtilAction | CUserMessage_UtilMsg_Response | Checks ConVars for unathorized modifications |
| CUserMessageRequestInventory | CUserMessage_Inventory_Response | Checks VMT pointers of global interfaces, checks if read-only sections of game DLLs were modified, checks something in entity system
| CUserMessageRequestDiagnostic | CUserMessage_Diagnostic_Response | Debugger detection |

## CUserMessage_Inventory_Response

### **VMT pointer check of global interfaces**

```cpp
// E8 ? ? ? ? 48 8D 8C 24 ? ? ? ? E8 ? ? ? ? F6 43 20 02 (relative jump) @ client.dll
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

<details>
<summary>List of checked interfaces</summary>

```text
VApplication001
VEngineCvar007
VStringTokenSystem001
TestScriptMgr001
VProcessUtils002
VFileSystem017
VAsyncFileSystem2_001
ResourceSystem013
ResourceManifestRegistry001
ResourceHandleUtils001
SchemaSystem_001
ResourceCompilerSystem001
VMaterialSystem2_001
PostProcessingSystem_001
InputSystemVersion001
InputStackSystemVersion001
RenderDeviceMgr001
RenderUtils_001
SoundSystem001
SoundOpSystemEdit001
SoundOpSystem001
SteamAudio001
VP4003
Localize_001
VMediaFoundation001
VAvi001
VBik001
MeshSystem001
MeshUtils001
RenderDevice003
VRenderDeviceSetupV001
RenderHardwareConfig002
SceneSystem_002
SceneUtils_001
WorldRendererMgr001
AssetSystem001
AssetSystemTest001
ParticleSystemMgr003
VScriptManager010
PropertyEditorSystem_001
MATCHFRAMEWORK_001
Source2V8System001
PanoramaUIEngine001
PanoramaUIClient001
PanoramaTextServices001
ToolFramework2_002
PhysicsBuilderMgr001
VisBuilder_001
BakedLODBuilderMgr001
HelpSystem_001
ToolSceneNodeFactory_001
EconItemToolModel_001
SchemaTestExternal_Two_001
SchemaTestExternal_One_001
AnimationSystem_001
AnimationSystemUtils_001
HammerMapLoader001
MaterialUtils_001
FontManager_001
TextLayout_001
AssetPreviewSystem_001
AssetBrowserSystem_001
AssetRenameSystem_001
VConComm001
MODEL_PROCESSING_SERVICES_INTERFACE_001
NetworkSystemVersion001
NetworkMessagesVersion001
FlattenedSerializersVersion001
SerializedEntitiesVersion001
DemoUpconverterVersion001
Source2Client002
Source2ClientUI001
Source2ClientPrediction001
Source2Server001
Source2Host001
Source2GameClients001
Source2GameEntities001
EngineServiceMgr001
HostStateMgr001
NetworkService_001
NetworkClientService_001
NetworkP2PService_001
NetworkServerService_001
ToolService_001
RenderService_001
StatsService_001
VProfService_001
InputService_001
MapListService_001
GameUIService_001
SoundService_001
BenchmarkService001
KeyValueCache001
GameResourceServiceClientV001
GameResourceServiceServerV001
Source2EngineToClient001
Source2EngineToServer001
Source2EngineToServerStringTable001
Source2EngineToClientStringTable001
VPhysics2_Interface_001
VPhysics2_Handle_Interface_001
ModelDocUtils001
AnimGraphEditorUtils001
MODEL_PROCESSING_SCRIPT_INTERFACE_001
EXPORTSYSTEM_INTERFACE_VERSION_001
NavSystem001
```

</details>

### **Integrity of read-only sections of game DLLs**

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
