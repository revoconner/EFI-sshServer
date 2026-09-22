/* Minimal UEFI definitions for a freestanding clang build. Only what this project uses, laid out per the UEFI 2.x specification. */

#ifndef UEFI_MIN_H_
#define UEFI_MIN_H_

#include <stdint.h>
#include <stddef.h>

typedef uint8_t   BOOLEAN;
typedef int64_t   INTN;
typedef uint64_t  UINTN;
typedef int8_t    INT8;
typedef uint8_t   UINT8;
typedef int16_t   INT16;
typedef uint16_t  UINT16;
typedef int32_t   INT32;
typedef uint32_t  UINT32;
typedef int64_t   INT64;
typedef uint64_t  UINT64;
typedef char      CHAR8;
typedef uint16_t  CHAR16;
typedef void      VOID;
typedef UINTN     EFI_STATUS;
typedef VOID     *EFI_HANDLE;
typedef VOID     *EFI_EVENT;
typedef UINTN     EFI_TPL;

#define IN
#define OUT
#define OPTIONAL
#define CONST const
#define STATIC static
#define TRUE  ((BOOLEAN)1)
#define FALSE ((BOOLEAN)0)
#ifndef NULL
#define NULL ((VOID *)0)
#endif
#define EFIAPI __attribute__((ms_abi))

typedef struct {
    UINT32 Data1;
    UINT16 Data2;
    UINT16 Data3;
    UINT8  Data4[8];
} EFI_GUID;

#define EFIERR(a)            (0x8000000000000000ULL | (a))
#define EFI_ERROR(s)         (((INTN)(s)) < 0)
#define EFI_SUCCESS          0
#define EFI_LOAD_ERROR       EFIERR(1)
#define EFI_INVALID_PARAMETER EFIERR(2)
#define EFI_UNSUPPORTED      EFIERR(3)
#define EFI_BAD_BUFFER_SIZE  EFIERR(4)
#define EFI_BUFFER_TOO_SMALL EFIERR(5)
#define EFI_NOT_READY        EFIERR(6)
#define EFI_DEVICE_ERROR     EFIERR(7)
#define EFI_WRITE_PROTECTED  EFIERR(8)
#define EFI_OUT_OF_RESOURCES EFIERR(9)
#define EFI_NOT_FOUND        EFIERR(14)
#define EFI_ACCESS_DENIED    EFIERR(15)
#define EFI_NO_RESPONSE      EFIERR(16)
#define EFI_NO_MAPPING       EFIERR(17)
#define EFI_TIMEOUT          EFIERR(18)
#define EFI_NOT_STARTED      EFIERR(19)
#define EFI_ALREADY_STARTED  EFIERR(20)
#define EFI_ABORTED          EFIERR(21)
#define EFI_CONNECTION_FIN   EFIERR(104)
#define EFI_CONNECTION_RESET EFIERR(105)
#define EFI_CONNECTION_REFUSED EFIERR(106)

#define TPL_APPLICATION 4
#define TPL_CALLBACK    8
#define TPL_NOTIFY      16
#define TPL_HIGH_LEVEL  31

#define EVT_TIMER          0x80000000
#define EVT_NOTIFY_WAIT    0x00000100
#define EVT_NOTIFY_SIGNAL  0x00000200

typedef enum {
    EfiReservedMemoryType,
    EfiLoaderCode,
    EfiLoaderData,
    EfiBootServicesCode,
    EfiBootServicesData,
    EfiRuntimeServicesCode,
    EfiRuntimeServicesData,
    EfiConventionalMemory,
    EfiUnusableMemory,
    EfiACPIReclaimMemory,
    EfiACPIMemoryNVS,
    EfiMemoryMappedIO,
    EfiMemoryMappedIOPortSpace,
    EfiPalCode,
    EfiPersistentMemory,
    EfiMaxMemoryType
} EFI_MEMORY_TYPE;

typedef enum {
    AllHandles,
    ByRegisterNotify,
    ByProtocol
} EFI_LOCATE_SEARCH_TYPE;

typedef enum {
    TimerCancel,
    TimerPeriodic,
    TimerRelative
} EFI_TIMER_DELAY;

#define EFI_OPEN_PROTOCOL_GET_PROTOCOL 0x00000002

typedef struct {
    UINT64 Signature;
    UINT32 Revision;
    UINT32 HeaderSize;
    UINT32 CRC32;
    UINT32 Reserved;
} EFI_TABLE_HEADER;

typedef struct {
    UINT16 Year;
    UINT8  Month;
    UINT8  Day;
    UINT8  Hour;
    UINT8  Minute;
    UINT8  Second;
    UINT8  Pad1;
    UINT32 Nanosecond;
    INT16  TimeZone;
    UINT8  Daylight;
    UINT8  Pad2;
} EFI_TIME;

typedef VOID (EFIAPI *EFI_EVENT_NOTIFY)(EFI_EVENT Event, VOID *Context);

/* Simple text input */

typedef struct {
    UINT16 ScanCode;
    CHAR16 UnicodeChar;
} EFI_INPUT_KEY;

#define SCAN_NULL      0x0000
#define SCAN_UP        0x0001
#define SCAN_DOWN      0x0002
#define SCAN_RIGHT     0x0003
#define SCAN_LEFT      0x0004
#define SCAN_HOME      0x0005
#define SCAN_END       0x0006
#define SCAN_INSERT    0x0007
#define SCAN_DELETE    0x0008
#define SCAN_PAGE_UP   0x0009
#define SCAN_PAGE_DOWN 0x000A
#define SCAN_F1        0x000B
#define SCAN_F2        0x000C
#define SCAN_F3        0x000D
#define SCAN_F4        0x000E
#define SCAN_F5        0x000F
#define SCAN_F6        0x0010
#define SCAN_F7        0x0011
#define SCAN_F8        0x0012
#define SCAN_F9        0x0013
#define SCAN_F10       0x0014
#define SCAN_F11       0x0015
#define SCAN_F12       0x0016
#define SCAN_ESC       0x0017

#define CHAR_BACKSPACE       0x0008
#define CHAR_TAB             0x0009
#define CHAR_LINEFEED        0x000A
#define CHAR_CARRIAGE_RETURN 0x000D

typedef struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL EFI_SIMPLE_TEXT_INPUT_PROTOCOL;
typedef EFI_STATUS (EFIAPI *EFI_INPUT_RESET)(EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This, BOOLEAN ExtendedVerification);
typedef EFI_STATUS (EFIAPI *EFI_INPUT_READ_KEY)(EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This, EFI_INPUT_KEY *Key);

struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL {
    EFI_INPUT_RESET    Reset;
    EFI_INPUT_READ_KEY ReadKeyStroke;
    EFI_EVENT          WaitForKey;
};

/* Simple text input ex */

#define EFI_SHIFT_STATE_VALID       0x80000000
#define EFI_RIGHT_SHIFT_PRESSED     0x00000001
#define EFI_LEFT_SHIFT_PRESSED      0x00000002
#define EFI_RIGHT_CONTROL_PRESSED   0x00000004
#define EFI_LEFT_CONTROL_PRESSED    0x00000008
#define EFI_RIGHT_ALT_PRESSED       0x00000010
#define EFI_LEFT_ALT_PRESSED        0x00000020
#define EFI_TOGGLE_STATE_VALID      0x80
#define EFI_KEY_STATE_EXPOSED       0x40

typedef UINT8 EFI_KEY_TOGGLE_STATE;

typedef struct {
    UINT32               KeyShiftState;
    EFI_KEY_TOGGLE_STATE KeyToggleState;
} EFI_KEY_STATE;

typedef struct {
    EFI_INPUT_KEY Key;
    EFI_KEY_STATE KeyState;
} EFI_KEY_DATA;

typedef struct _EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL;
typedef EFI_STATUS (EFIAPI *EFI_KEY_NOTIFY_FUNCTION)(EFI_KEY_DATA *KeyData);
typedef EFI_STATUS (EFIAPI *EFI_INPUT_RESET_EX)(EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This, BOOLEAN ExtendedVerification);
typedef EFI_STATUS (EFIAPI *EFI_INPUT_READ_KEY_EX)(EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This, EFI_KEY_DATA *KeyData);
typedef EFI_STATUS (EFIAPI *EFI_SET_STATE)(EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This, EFI_KEY_TOGGLE_STATE *KeyToggleState);
typedef EFI_STATUS (EFIAPI *EFI_REGISTER_KEYSTROKE_NOTIFY)(EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This, EFI_KEY_DATA *KeyData, EFI_KEY_NOTIFY_FUNCTION KeyNotificationFunction, VOID **NotifyHandle);
typedef EFI_STATUS (EFIAPI *EFI_UNREGISTER_KEYSTROKE_NOTIFY)(EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This, VOID *NotificationHandle);

struct _EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL {
    EFI_INPUT_RESET_EX              Reset;
    EFI_INPUT_READ_KEY_EX           ReadKeyStrokeEx;
    EFI_EVENT                       WaitForKeyEx;
    EFI_SET_STATE                   SetState;
    EFI_REGISTER_KEYSTROKE_NOTIFY   RegisterKeyNotify;
    EFI_UNREGISTER_KEYSTROKE_NOTIFY UnregisterKeyNotify;
};

/* Simple text output */

typedef struct {
    INT32   MaxMode;
    INT32   Mode;
    INT32   Attribute;
    INT32   CursorColumn;
    INT32   CursorRow;
    BOOLEAN CursorVisible;
} SIMPLE_TEXT_OUTPUT_MODE;

typedef struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;
typedef EFI_STATUS (EFIAPI *EFI_TEXT_RESET)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, BOOLEAN ExtendedVerification);
typedef EFI_STATUS (EFIAPI *EFI_TEXT_STRING)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, CHAR16 *String);
typedef EFI_STATUS (EFIAPI *EFI_TEXT_TEST_STRING)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, CHAR16 *String);
typedef EFI_STATUS (EFIAPI *EFI_TEXT_QUERY_MODE)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, UINTN ModeNumber, UINTN *Columns, UINTN *Rows);
typedef EFI_STATUS (EFIAPI *EFI_TEXT_SET_MODE)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, UINTN ModeNumber);
typedef EFI_STATUS (EFIAPI *EFI_TEXT_SET_ATTRIBUTE)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, UINTN Attribute);
typedef EFI_STATUS (EFIAPI *EFI_TEXT_CLEAR_SCREEN)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This);
typedef EFI_STATUS (EFIAPI *EFI_TEXT_SET_CURSOR_POSITION)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, UINTN Column, UINTN Row);
typedef EFI_STATUS (EFIAPI *EFI_TEXT_ENABLE_CURSOR)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, BOOLEAN Visible);

struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL {
    EFI_TEXT_RESET               Reset;
    EFI_TEXT_STRING              OutputString;
    EFI_TEXT_TEST_STRING         TestString;
    EFI_TEXT_QUERY_MODE          QueryMode;
    EFI_TEXT_SET_MODE            SetMode;
    EFI_TEXT_SET_ATTRIBUTE       SetAttribute;
    EFI_TEXT_CLEAR_SCREEN        ClearScreen;
    EFI_TEXT_SET_CURSOR_POSITION SetCursorPosition;
    EFI_TEXT_ENABLE_CURSOR       EnableCursor;
    SIMPLE_TEXT_OUTPUT_MODE     *Mode;
};

/* Device path */

#pragma pack(1)
typedef struct {
    UINT8 Type;
    UINT8 SubType;
    UINT8 Length[2];
} EFI_DEVICE_PATH_PROTOCOL;
#pragma pack()

#define MEDIA_DEVICE_PATH     0x04
#define MEDIA_FILEPATH_DP     0x04
#define END_DEVICE_PATH_TYPE  0x7f
#define END_ENTIRE_DEVICE_PATH_SUBTYPE 0xff

/* Loaded image */

typedef struct _EFI_SYSTEM_TABLE EFI_SYSTEM_TABLE;
typedef EFI_STATUS (EFIAPI *EFI_IMAGE_UNLOAD)(EFI_HANDLE ImageHandle);

typedef struct {
    UINT32                    Revision;
    EFI_HANDLE                ParentHandle;
    EFI_SYSTEM_TABLE         *SystemTable;
    EFI_HANDLE                DeviceHandle;
    EFI_DEVICE_PATH_PROTOCOL *FilePath;
    VOID                     *Reserved;
    UINT32                    LoadOptionsSize;
    VOID                     *LoadOptions;
    VOID                     *ImageBase;
    UINT64                    ImageSize;
    EFI_MEMORY_TYPE           ImageCodeType;
    EFI_MEMORY_TYPE           ImageDataType;
    EFI_IMAGE_UNLOAD          Unload;
} EFI_LOADED_IMAGE_PROTOCOL;

/* Firmware volume 2, only ReadSection is used */

typedef struct _EFI_FIRMWARE_VOLUME2_PROTOCOL EFI_FIRMWARE_VOLUME2_PROTOCOL;
typedef UINT8 EFI_SECTION_TYPE;
#define EFI_SECTION_PE32 0x10
typedef EFI_STATUS (EFIAPI *EFI_FV_READ_SECTION)(EFI_FIRMWARE_VOLUME2_PROTOCOL *This, CONST EFI_GUID *NameGuid, EFI_SECTION_TYPE SectionType, UINTN SectionInstance, VOID **Buffer, UINTN *BufferSize, UINT32 *AuthenticationStatus);

struct _EFI_FIRMWARE_VOLUME2_PROTOCOL {
    VOID               *GetVolumeAttributes;
    VOID               *SetVolumeAttributes;
    VOID               *ReadFile;
    EFI_FV_READ_SECTION ReadSection;
    VOID               *WriteFile;
    VOID               *GetNextFile;
    UINT32              KeySize;
    EFI_HANDLE          ParentHandle;
    VOID               *GetInfo;
    VOID               *SetInfo;
};

/* RNG protocol */

typedef struct _EFI_RNG_PROTOCOL EFI_RNG_PROTOCOL;
typedef EFI_STATUS (EFIAPI *EFI_RNG_GET_INFO)(EFI_RNG_PROTOCOL *This, UINTN *RNGAlgorithmListSize, EFI_GUID *RNGAlgorithmList);
typedef EFI_STATUS (EFIAPI *EFI_RNG_GET_RNG)(EFI_RNG_PROTOCOL *This, EFI_GUID *RNGAlgorithm, UINTN RNGValueLength, UINT8 *RNGValue);

struct _EFI_RNG_PROTOCOL {
    EFI_RNG_GET_INFO GetInfo;
    EFI_RNG_GET_RNG  GetRNG;
};

/* Service binding */

typedef struct _EFI_SERVICE_BINDING_PROTOCOL EFI_SERVICE_BINDING_PROTOCOL;
typedef EFI_STATUS (EFIAPI *EFI_SERVICE_BINDING_CREATE_CHILD)(EFI_SERVICE_BINDING_PROTOCOL *This, EFI_HANDLE *ChildHandle);
typedef EFI_STATUS (EFIAPI *EFI_SERVICE_BINDING_DESTROY_CHILD)(EFI_SERVICE_BINDING_PROTOCOL *This, EFI_HANDLE ChildHandle);

struct _EFI_SERVICE_BINDING_PROTOCOL {
    EFI_SERVICE_BINDING_CREATE_CHILD  CreateChild;
    EFI_SERVICE_BINDING_DESTROY_CHILD DestroyChild;
};

/* TCP4 */

typedef struct {
    UINT8 Addr[4];
} EFI_IPv4_ADDRESS;

typedef struct {
    BOOLEAN          UseDefaultAddress;
    EFI_IPv4_ADDRESS StationAddress;
    EFI_IPv4_ADDRESS SubnetMask;
    UINT16           StationPort;
    EFI_IPv4_ADDRESS RemoteAddress;
    UINT16           RemotePort;
    BOOLEAN          ActiveFlag;
} EFI_TCP4_ACCESS_POINT;

typedef struct {
    UINT32  ReceiveBufferSize;
    UINT32  SendBufferSize;
    UINT32  MaxSynBackLog;
    UINT32  ConnectionTimeout;
    UINT32  DataRetries;
    UINT32  FinTimeout;
    UINT32  TimeWaitTimeout;
    UINT32  KeepAliveProbes;
    UINT32  KeepAliveTime;
    UINT32  KeepAliveInterval;
    BOOLEAN EnableNagle;
    BOOLEAN EnableTimeStamp;
    BOOLEAN EnableWindowScaling;
    BOOLEAN EnableSelectiveAck;
    BOOLEAN EnablePathMtuDiscovery;
} EFI_TCP4_OPTION;

typedef struct {
    UINT8                 TypeOfService;
    UINT8                 TimeToLive;
    EFI_TCP4_ACCESS_POINT AccessPoint;
    EFI_TCP4_OPTION      *ControlOption;
} EFI_TCP4_CONFIG_DATA;

typedef enum {
    Tcp4StateClosed      = 0,
    Tcp4StateListen      = 1,
    Tcp4StateSynSent     = 2,
    Tcp4StateSynReceived = 3,
    Tcp4StateEstablished = 4,
    Tcp4StateFinWait1    = 5,
    Tcp4StateFinWait2    = 6,
    Tcp4StateClosing     = 7,
    Tcp4StateTimeWait    = 8,
    Tcp4StateCloseWait   = 9,
    Tcp4StateLastAck     = 10
} EFI_TCP4_CONNECTION_STATE;

typedef struct {
    EFI_EVENT  Event;
    EFI_STATUS Status;
} EFI_TCP4_COMPLETION_TOKEN;

typedef struct {
    EFI_TCP4_COMPLETION_TOKEN CompletionToken;
} EFI_TCP4_CONNECTION_TOKEN;

typedef struct {
    EFI_TCP4_COMPLETION_TOKEN CompletionToken;
    EFI_HANDLE                NewChildHandle;
} EFI_TCP4_LISTEN_TOKEN;

typedef struct {
    UINT32 FragmentLength;
    VOID  *FragmentBuffer;
} EFI_TCP4_FRAGMENT_DATA;

typedef struct {
    BOOLEAN                UrgentFlag;
    UINT32                 DataLength;
    UINT32                 FragmentCount;
    EFI_TCP4_FRAGMENT_DATA FragmentTable[1];
} EFI_TCP4_RECEIVE_DATA;

typedef struct {
    BOOLEAN                Push;
    BOOLEAN                Urgent;
    UINT32                 DataLength;
    UINT32                 FragmentCount;
    EFI_TCP4_FRAGMENT_DATA FragmentTable[1];
} EFI_TCP4_TRANSMIT_DATA;

typedef struct {
    EFI_TCP4_COMPLETION_TOKEN CompletionToken;
    union {
        EFI_TCP4_RECEIVE_DATA  *RxData;
        EFI_TCP4_TRANSMIT_DATA *TxData;
    } Packet;
} EFI_TCP4_IO_TOKEN;

typedef struct {
    EFI_TCP4_COMPLETION_TOKEN CompletionToken;
    BOOLEAN                   AbortOnClose;
} EFI_TCP4_CLOSE_TOKEN;

typedef struct _EFI_TCP4_PROTOCOL EFI_TCP4_PROTOCOL;
typedef EFI_STATUS (EFIAPI *EFI_TCP4_GET_MODE_DATA)(EFI_TCP4_PROTOCOL *This, EFI_TCP4_CONNECTION_STATE *Tcp4State, EFI_TCP4_CONFIG_DATA *Tcp4ConfigData, VOID *Ip4ModeData, VOID *MnpConfigData, VOID *SnpModeData);
typedef EFI_STATUS (EFIAPI *EFI_TCP4_CONFIGURE)(EFI_TCP4_PROTOCOL *This, EFI_TCP4_CONFIG_DATA *TcpConfigData);
typedef EFI_STATUS (EFIAPI *EFI_TCP4_ROUTES)(EFI_TCP4_PROTOCOL *This, BOOLEAN DeleteRoute, EFI_IPv4_ADDRESS *SubnetAddress, EFI_IPv4_ADDRESS *SubnetMask, EFI_IPv4_ADDRESS *GatewayAddress);
typedef EFI_STATUS (EFIAPI *EFI_TCP4_CONNECT)(EFI_TCP4_PROTOCOL *This, EFI_TCP4_CONNECTION_TOKEN *ConnectionToken);
typedef EFI_STATUS (EFIAPI *EFI_TCP4_ACCEPT)(EFI_TCP4_PROTOCOL *This, EFI_TCP4_LISTEN_TOKEN *ListenToken);
typedef EFI_STATUS (EFIAPI *EFI_TCP4_TRANSMIT)(EFI_TCP4_PROTOCOL *This, EFI_TCP4_IO_TOKEN *Token);
typedef EFI_STATUS (EFIAPI *EFI_TCP4_RECEIVE)(EFI_TCP4_PROTOCOL *This, EFI_TCP4_IO_TOKEN *Token);
typedef EFI_STATUS (EFIAPI *EFI_TCP4_CLOSE)(EFI_TCP4_PROTOCOL *This, EFI_TCP4_CLOSE_TOKEN *CloseToken);
typedef EFI_STATUS (EFIAPI *EFI_TCP4_CANCEL)(EFI_TCP4_PROTOCOL *This, EFI_TCP4_COMPLETION_TOKEN *Token);
typedef EFI_STATUS (EFIAPI *EFI_TCP4_POLL)(EFI_TCP4_PROTOCOL *This);

struct _EFI_TCP4_PROTOCOL {
    EFI_TCP4_GET_MODE_DATA GetModeData;
    EFI_TCP4_CONFIGURE     Configure;
    EFI_TCP4_ROUTES        Routes;
    EFI_TCP4_CONNECT       Connect;
    EFI_TCP4_ACCEPT        Accept;
    EFI_TCP4_TRANSMIT      Transmit;
    EFI_TCP4_RECEIVE       Receive;
    EFI_TCP4_CLOSE         Close;
    EFI_TCP4_CANCEL        Cancel;
    EFI_TCP4_POLL          Poll;
};

/* Boot services. Every slot is a pointer, unused ones are left as VOID * to keep the layout. */

typedef EFI_TPL    (EFIAPI *EFI_RAISE_TPL)(EFI_TPL NewTpl);
typedef VOID       (EFIAPI *EFI_RESTORE_TPL)(EFI_TPL OldTpl);
typedef EFI_STATUS (EFIAPI *EFI_ALLOCATE_POOL)(EFI_MEMORY_TYPE PoolType, UINTN Size, VOID **Buffer);
typedef EFI_STATUS (EFIAPI *EFI_FREE_POOL)(VOID *Buffer);
typedef EFI_STATUS (EFIAPI *EFI_CREATE_EVENT)(UINT32 Type, EFI_TPL NotifyTpl, EFI_EVENT_NOTIFY NotifyFunction, VOID *NotifyContext, EFI_EVENT *Event);
typedef EFI_STATUS (EFIAPI *EFI_SET_TIMER)(EFI_EVENT Event, EFI_TIMER_DELAY Type, UINT64 TriggerTime);
typedef EFI_STATUS (EFIAPI *EFI_WAIT_FOR_EVENT)(UINTN NumberOfEvents, EFI_EVENT *Event, UINTN *Index);
typedef EFI_STATUS (EFIAPI *EFI_SIGNAL_EVENT)(EFI_EVENT Event);
typedef EFI_STATUS (EFIAPI *EFI_CLOSE_EVENT)(EFI_EVENT Event);
typedef EFI_STATUS (EFIAPI *EFI_CHECK_EVENT)(EFI_EVENT Event);
typedef EFI_STATUS (EFIAPI *EFI_HANDLE_PROTOCOL)(EFI_HANDLE Handle, EFI_GUID *Protocol, VOID **Interface);
typedef EFI_STATUS (EFIAPI *EFI_IMAGE_LOAD)(BOOLEAN BootPolicy, EFI_HANDLE ParentImageHandle, EFI_DEVICE_PATH_PROTOCOL *DevicePath, VOID *SourceBuffer, UINTN SourceSize, EFI_HANDLE *ImageHandle);
typedef EFI_STATUS (EFIAPI *EFI_IMAGE_START)(EFI_HANDLE ImageHandle, UINTN *ExitDataSize, CHAR16 **ExitData);
typedef EFI_STATUS (EFIAPI *EFI_IMAGE_UNLOAD_BS)(EFI_HANDLE ImageHandle);
typedef EFI_STATUS (EFIAPI *EFI_STALL)(UINTN Microseconds);
typedef EFI_STATUS (EFIAPI *EFI_SET_WATCHDOG_TIMER)(UINTN Timeout, UINT64 WatchdogCode, UINTN DataSize, CHAR16 *WatchdogData);
typedef EFI_STATUS (EFIAPI *EFI_OPEN_PROTOCOL)(EFI_HANDLE Handle, EFI_GUID *Protocol, VOID **Interface, EFI_HANDLE AgentHandle, EFI_HANDLE ControllerHandle, UINT32 Attributes);
typedef EFI_STATUS (EFIAPI *EFI_CLOSE_PROTOCOL)(EFI_HANDLE Handle, EFI_GUID *Protocol, EFI_HANDLE AgentHandle, EFI_HANDLE ControllerHandle);
typedef EFI_STATUS (EFIAPI *EFI_LOCATE_HANDLE_BUFFER)(EFI_LOCATE_SEARCH_TYPE SearchType, EFI_GUID *Protocol, VOID *SearchKey, UINTN *NoHandles, EFI_HANDLE **Buffer);
typedef EFI_STATUS (EFIAPI *EFI_LOCATE_PROTOCOL)(EFI_GUID *Protocol, VOID *Registration, VOID **Interface);
typedef EFI_STATUS (EFIAPI *EFI_INSTALL_MULTIPLE_PROTOCOL_INTERFACES)(EFI_HANDLE *Handle, ...);
typedef EFI_STATUS (EFIAPI *EFI_UNINSTALL_MULTIPLE_PROTOCOL_INTERFACES)(EFI_HANDLE Handle, ...);
typedef EFI_STATUS (EFIAPI *EFI_CALCULATE_CRC32)(VOID *Data, UINTN DataSize, UINT32 *Crc32);
typedef VOID       (EFIAPI *EFI_COPY_MEM)(VOID *Destination, VOID *Source, UINTN Length);
typedef VOID       (EFIAPI *EFI_SET_MEM)(VOID *Buffer, UINTN Size, UINT8 Value);

typedef struct {
    EFI_TABLE_HEADER  Hdr;
    EFI_RAISE_TPL     RaiseTPL;
    EFI_RESTORE_TPL   RestoreTPL;
    VOID             *AllocatePages;
    VOID             *FreePages;
    VOID             *GetMemoryMap;
    EFI_ALLOCATE_POOL AllocatePool;
    EFI_FREE_POOL     FreePool;
    EFI_CREATE_EVENT  CreateEvent;
    EFI_SET_TIMER     SetTimer;
    EFI_WAIT_FOR_EVENT WaitForEvent;
    EFI_SIGNAL_EVENT  SignalEvent;
    EFI_CLOSE_EVENT   CloseEvent;
    EFI_CHECK_EVENT   CheckEvent;
    VOID             *InstallProtocolInterface;
    VOID             *ReinstallProtocolInterface;
    VOID             *UninstallProtocolInterface;
    EFI_HANDLE_PROTOCOL HandleProtocol;
    VOID             *Reserved;
    VOID             *RegisterProtocolNotify;
    VOID             *LocateHandle;
    VOID             *LocateDevicePath;
    VOID             *InstallConfigurationTable;
    EFI_IMAGE_LOAD    LoadImage;
    EFI_IMAGE_START   StartImage;
    VOID             *Exit;
    EFI_IMAGE_UNLOAD_BS UnloadImage;
    VOID             *ExitBootServices;
    VOID             *GetNextMonotonicCount;
    EFI_STALL         Stall;
    EFI_SET_WATCHDOG_TIMER SetWatchdogTimer;
    VOID             *ConnectController;
    VOID             *DisconnectController;
    EFI_OPEN_PROTOCOL OpenProtocol;
    EFI_CLOSE_PROTOCOL CloseProtocol;
    VOID             *OpenProtocolInformation;
    VOID             *ProtocolsPerHandle;
    EFI_LOCATE_HANDLE_BUFFER LocateHandleBuffer;
    EFI_LOCATE_PROTOCOL LocateProtocol;
    EFI_INSTALL_MULTIPLE_PROTOCOL_INTERFACES   InstallMultipleProtocolInterfaces;
    EFI_UNINSTALL_MULTIPLE_PROTOCOL_INTERFACES UninstallMultipleProtocolInterfaces;
    EFI_CALCULATE_CRC32 CalculateCrc32;
    EFI_COPY_MEM      CopyMem;
    EFI_SET_MEM       SetMem;
    VOID             *CreateEventEx;
} EFI_BOOT_SERVICES;

typedef EFI_STATUS (EFIAPI *EFI_GET_TIME)(EFI_TIME *Time, VOID *Capabilities);

typedef struct {
    EFI_TABLE_HEADER Hdr;
    EFI_GET_TIME     GetTime;
    VOID            *SetTime;
    VOID            *GetWakeupTime;
    VOID            *SetWakeupTime;
    VOID            *SetVirtualAddressMap;
    VOID            *ConvertPointer;
    VOID            *GetVariable;
    VOID            *GetNextVariableName;
    VOID            *SetVariable;
    VOID            *GetNextHighMonotonicCount;
    VOID            *ResetSystem;
    VOID            *UpdateCapsule;
    VOID            *QueryCapsuleCapabilities;
    VOID            *QueryVariableInfo;
} EFI_RUNTIME_SERVICES;

struct _EFI_SYSTEM_TABLE {
    EFI_TABLE_HEADER                 Hdr;
    CHAR16                          *FirmwareVendor;
    UINT32                           FirmwareRevision;
    EFI_HANDLE                       ConsoleInHandle;
    EFI_SIMPLE_TEXT_INPUT_PROTOCOL  *ConIn;
    EFI_HANDLE                       ConsoleOutHandle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut;
    EFI_HANDLE                       StandardErrorHandle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *StdErr;
    EFI_RUNTIME_SERVICES            *RuntimeServices;
    EFI_BOOT_SERVICES               *BootServices;
    UINTN                            NumberOfTableEntries;
    VOID                            *ConfigurationTable;
};

/* GUIDs, defined in uefirt.c */

extern EFI_GUID gEfiSimpleTextInProtocolGuid;
extern EFI_GUID gEfiSimpleTextInputExProtocolGuid;
extern EFI_GUID gEfiSimpleTextOutProtocolGuid;
extern EFI_GUID gEfiLoadedImageProtocolGuid;
extern EFI_GUID gEfiDevicePathProtocolGuid;
extern EFI_GUID gEfiTcp4ServiceBindingProtocolGuid;
extern EFI_GUID gEfiTcp4ProtocolGuid;
extern EFI_GUID gEfiFirmwareVolume2ProtocolGuid;
extern EFI_GUID gEfiRngProtocolGuid;

#endif
