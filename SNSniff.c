/**
  SNSniff - Приложение для чтения и проверки серийных номеров и MAC адресов из UEFI переменных.
**/

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>
#include <Library/ShellLib.h>
#include <Library/ShellCEntryLib.h>
#include <Library/BaseLib.h>
#include <Library/FileHandleLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/DevicePath.h>
#include <Guid/GlobalVariable.h>
#include <Guid/FileInfo.h>
#include <IndustryStandard/SmBios.h>
#include <Protocol/Smbios.h>

// Стандартные GUID для переменных
static EFI_GUID mCustomVarGuid = {
  0x12345678, 0x1234, 0x1234, {0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}
};

static EFI_GUID mGlobalVarGuid = EFI_GLOBAL_VARIABLE;

// Дополнительные распространенные GUID
static EFI_GUID mMsftVarGuid = {
  0x77FA9ABD, 0x0359, 0x4D32, {0xBD, 0x60, 0x28, 0xF4, 0xE7, 0x8F, 0x78, 0x4B}
};

static EFI_GUID mSystemVarGuid = {
  0xEC87D643, 0xEBA4, 0x4BB5, {0xA1, 0xE5, 0x3F, 0x3E, 0x36, 0xB2, 0x0D, 0xA9}
};

// Структура для хранения GUID
typedef struct {
  EFI_GUID  *Guid;
  CHAR16    *Name;
} GUID_ENTRY;

// Максимальная длина для буферов
#define MAX_BUFFER_SIZE 256

// Определения для типов SMBIOS записей
#define SMBIOS_TYPE_SYSTEM_INFORMATION    1
#define SMBIOS_TYPE_BASEBOARD_INFORMATION 2

// Массив известных GUID
GUID_ENTRY mKnownGuids[] = {
  {&mCustomVarGuid,  L"Custom"},
  {&mGlobalVarGuid,  L"Global"},
  {&mMsftVarGuid,    L"Microsoft"},
  {&mSystemVarGuid,  L"System"},
  {NULL, NULL}
};

// Перечисление типов вывода
typedef enum {
  OUTPUT_ALL,
  OUTPUT_HEX,
  OUTPUT_ASCII,
  OUTPUT_UCS
} OUTPUT_TYPE;

// Структура конфигурации для проверки SN и MAC
typedef struct {
  CHAR16    *SerialVarName;         // Имя переменной UEFI с серийным номером для прошивки/проверки
  CHAR16    *MacVarName;            // Имя переменной UEFI с MAC-адресом для проверки
  CHAR16    *AmideEfiPath;          // Путь к AMIDEEFIx64.efi
  BOOLEAN   CheckSn;                // Флаг проверки SN
  BOOLEAN   CheckMac;               // Флаг проверки MAC
  BOOLEAN   CheckOnly;              // Флаг режима только проверки без прошивки
  EFI_GUID  *SerialVarGuid;         // GUID для переменной с серийным номером
  EFI_GUID  *MacVarGuid;            // GUID для переменной с MAC-адресом
} CHECK_CONFIG;

// Прототипы функций
EFI_STATUS
RebootToBoot (
  VOID
  );

EFI_STATUS
RunAmideefi (
  IN CONST CHAR16    *AmideEfiPath,
  IN CONST CHAR16    *SerialNumber
  );

BOOLEAN
CheckSerialNumber (
  IN  CONST CHAR16    *SerialVarName,
  IN  EFI_GUID        *SerialVarGuid
  );

EFI_STATUS
GetSystemSerialNumber (
  OUT CHAR16    *SystemSerialNumber,
  IN  UINTN     BufferSize
  );

EFI_STATUS
GetBaseBoardSerialNumber (
  OUT CHAR16    *BaseBoardSerialNumber,
  IN  UINTN     BufferSize
  );

EFI_STATUS
GetSmbiosString (
  IN  UINT8     StringNumber,
  IN  CHAR8     *StringTable,
  OUT CHAR16    *StringBuffer,
  IN  UINTN     StringBufferSize
  );

VOID
PrintSystemInfo (
  VOID
  );

EFI_STATUS
DisplayBaseBoardInfo (
  VOID
  );

/**
  Функция для вывода HEX-дампа данных.
  
  @param Data     Указатель на данные
  @param DataSize Размер данных в байтах
**/
VOID
PrintHexDump (
  IN CONST VOID  *Data,
  IN UINTN       DataSize
  )
{
  CONST UINT8 *Bytes;
  UINTN       Index;
  
  Bytes = (CONST UINT8*)Data;
  
  for (Index = 0; Index < DataSize; Index++) {
    Print (L"%02X ", Bytes[Index]);
    
    // Перенос строки каждые 16 байт для удобства чтения
    if ((Index + 1) % 16 == 0) {
      Print (L"\n");
    }
  }
  
  // Добавляем перенос строки, если последняя строка не закончилась им
  if (DataSize % 16 != 0) {
    Print (L"\n");
  }
}

/**
  Функция для вывода данных в виде ASCII-строки.
  
  @param Data     Указатель на данные
  @param DataSize Размер данных в байтах
**/
VOID
PrintAsciiString (
  IN CONST VOID  *Data,
  IN UINTN       DataSize
  )
{
  UINT8 *AsciiData = (UINT8*)Data;
  for (UINTN Index = 0; Index < DataSize; Index++) {
    // Выводим только печатаемые ASCII символы
    if (AsciiData[Index] >= 0x20 && AsciiData[Index] <= 0x7E) {
      Print (L"%c", AsciiData[Index]);
    } else if (AsciiData[Index] == 0) {
      // Нулевой байт - конец строки
      break;
    } else {
      // Непечатаемый символ
      Print (L".");
    }
  }
  Print (L"\n");
}

/**
  Функция для вывода данных в виде UCS-2 строки.
  
  @param Data     Указатель на данные
  @param DataSize Размер данных в байтах
**/
VOID
PrintUcsString (
  IN CONST VOID  *Data,
  IN UINTN       DataSize
  )
{
  if (DataSize >= 2) { // Хотя бы один символ CHAR16
    Print (L"%s\n", (CHAR16*)Data);
  } else {
    Print (L"(too small for UCS-2 string)\n");
  }
}

/**
  Функция парсинга GUID из строки.
  
  @param GuidString  Строка с GUID или префиксом GUID
  @param Guid        Указатель на структуру EFI_GUID для результата
  
  @retval TRUE       GUID или префикс успешно распарсен
  @retval FALSE      Ошибка при парсинге
**/
BOOLEAN
ParseGuidPrefix (
  IN  CONST CHAR16  *GuidString,
  OUT EFI_GUID      *Guid
  )
{
  UINTN     BufferLen;
  CHAR16    *TempBuffer;
  BOOLEAN   Result;
  
  if (GuidString == NULL || Guid == NULL) {
    return FALSE;
  }
  
  // Проверка длины строки
  BufferLen = StrLen (GuidString);
  if (BufferLen < 1) {
    return FALSE;
  }
  
  // Если строка короче полного GUID, дополняем её символами
  if (BufferLen < 36) {
    TempBuffer = AllocateZeroPool ((36 + 1) * sizeof (CHAR16));
    if (TempBuffer == NULL) {
      return FALSE;
    }
    
    // Копируем префикс и дополняем остаток нулями
    StrCpyS (TempBuffer, 37, GuidString);
    for (UINTN i = BufferLen; i < 36; i++) {
      if (i == 8 || i == 13 || i == 18 || i == 23) {
        TempBuffer[i] = L'-';
      } else {
        TempBuffer[i] = L'0';
      }
    }
    
    // Парсим полученный GUID
    Result = StrToGuid (TempBuffer, Guid);
    FreePool (TempBuffer);
    return Result;
  } else {
    // Полный GUID, парсим напрямую
    return StrToGuid (GuidString, Guid);
  }
}

/**
  Получает содержимое переменной UEFI.

  @param VariableName   Имя переменной
  @param VariableGuid   GUID переменной
  @param VariableData   Указатель на буфер для данных (будет выделен)
  @param VariableSize   Указатель на размер данных

  @retval EFI_SUCCESS   Переменная успешно прочитана
  @retval другое        Ошибка при чтении переменной
**/
EFI_STATUS
GetVariableData (
  IN  CONST CHAR16    *VariableName,
  IN  EFI_GUID        *VariableGuid,
  OUT VOID            **VariableData,
  OUT UINTN           *VariableSize
  )
{
  EFI_STATUS  Status;
  UINT32      Attributes = 0;
  
  // Проверяем входные параметры
  if (VariableName == NULL || VariableGuid == NULL || 
      VariableData == NULL || VariableSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  // Инициализируем выходные параметры
  *VariableData = NULL;
  *VariableSize = 0;
  
  // Получаем размер переменной
  Status = gRT->GetVariable (
                  (CHAR16*)VariableName,
                  VariableGuid,
                  &Attributes,
                  VariableSize,
                  NULL
                  );
                  
  if (Status == EFI_BUFFER_TOO_SMALL) {
    // Выделяем память для данных
    *VariableData = AllocateZeroPool (*VariableSize);
    if (*VariableData == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }
    
    // Получаем значение переменной
    Status = gRT->GetVariable (
                    (CHAR16*)VariableName,
                    VariableGuid,
                    &Attributes,
                    VariableSize,
                    *VariableData
                    );
                    
    if (EFI_ERROR (Status)) {
      FreePool (*VariableData);
      *VariableData = NULL;
      *VariableSize = 0;
    }
  }
  
  return Status;
}

/**
  Функция поиска переменной по имени и префиксу GUID.
  
  @param VariableName   Имя искомой переменной
  @param GuidPrefix     Префикс GUID (может быть NULL)
  @param OutputType     Тип вывода
  
  @retval EFI_SUCCESS   Переменная найдена и выведена
  @retval другое        Ошибка при поиске или выводе
**/
EFI_STATUS
FindAndPrintVariable (
  IN CONST CHAR16    *VariableName,
  IN CONST CHAR16    *GuidPrefix,
  IN OUTPUT_TYPE     OutputType
  )
{
  EFI_STATUS  Status;
  VOID        *VariableData = NULL;
  UINTN       VariableSize = 0;
  UINT32      Attributes = 0;
  EFI_GUID    TargetGuid;
  BOOLEAN     GuidSpecified = FALSE;
  UINTN       Index;
  BOOLEAN     Found = FALSE;
  
  // Если указан префикс GUID, пытаемся его распарсить
  if (GuidPrefix != NULL && StrLen (GuidPrefix) > 0) {
    GuidSpecified = ParseGuidPrefix (GuidPrefix, &TargetGuid);
    if (!GuidSpecified) {
      Print (L"Error: Invalid GUID prefix '%s'\n", GuidPrefix);
      return EFI_INVALID_PARAMETER;
    }
  }
  
  // Если GUID не указан, ищем по всем известным GUID
  if (!GuidSpecified) {
    for (Index = 0; mKnownGuids[Index].Guid != NULL; Index++) {
      // Сначала узнаем размер переменной
      VariableSize = 0;
      Status = gRT->GetVariable (
                      (CHAR16*)VariableName,
                      mKnownGuids[Index].Guid,
                      &Attributes,
                      &VariableSize,
                      NULL
                      );
                      
      if (Status == EFI_BUFFER_TOO_SMALL) {
        // Переменная найдена, выделяем память и получаем данные
        if (VariableData != NULL) {
          FreePool (VariableData);
        }
        
        VariableData = AllocateZeroPool (VariableSize);
        if (VariableData == NULL) {
          Print (L"Error: Failed to allocate memory\n");
          return EFI_OUT_OF_RESOURCES;
        }
        
        Status = gRT->GetVariable (
                        (CHAR16*)VariableName,
                        mKnownGuids[Index].Guid,
                        &Attributes,
                        &VariableSize,
                        VariableData
                        );
                        
        if (!EFI_ERROR (Status)) {
          Found = TRUE;
          
          // Если режим вывода не "только данные", выводим информацию о переменной
          if (OutputType == OUTPUT_ALL) {
            Print (L"Variable Name: %s\n", VariableName);
            Print (L"GUID: %s\n", mKnownGuids[Index].Name);
            Print (L"Size: %d bytes\n", VariableSize);
            Print (L"Attributes: 0x%08X\n\n", Attributes);
            
            Print (L"Hexadecimal dump:\n");
            PrintHexDump (VariableData, VariableSize);
            
            Print (L"\nAs string (UCS-2): ");
            PrintUcsString (VariableData, VariableSize);
            
            Print (L"As string (ASCII): ");
            PrintAsciiString (VariableData, VariableSize);
          } else {
            // Выводим только в указанном формате
            switch (OutputType) {
              case OUTPUT_HEX:
                PrintHexDump (VariableData, VariableSize);
                break;
              case OUTPUT_ASCII:
                PrintAsciiString (VariableData, VariableSize);
                break;
              case OUTPUT_UCS:
                PrintUcsString (VariableData, VariableSize);
                break;
              default:
                break;
            }
          }
          
          break; // Переменная найдена, выходим из цикла
        }
      }
    }
  } else {
    // Ищем по указанному GUID
    // Сначала узнаем размер переменной
    VariableSize = 0;
    Status = gRT->GetVariable (
                    (CHAR16*)VariableName,
                    &TargetGuid,
                    &Attributes,
                    &VariableSize,
                    NULL
                    );
                    
    if (Status == EFI_BUFFER_TOO_SMALL) {
      // Переменная найдена, выделяем память и получаем данные
      VariableData = AllocateZeroPool (VariableSize);
      if (VariableData == NULL) {
        Print (L"Error: Failed to allocate memory\n");
        return EFI_OUT_OF_RESOURCES;
      }
      
      Status = gRT->GetVariable (
                      (CHAR16*)VariableName,
                      &TargetGuid,
                      &Attributes,
                      &VariableSize,
                      VariableData
                      );
                      
      if (!EFI_ERROR (Status)) {
        Found = TRUE;
        
        // Если режим вывода не "только данные", выводим информацию о переменной
        if (OutputType == OUTPUT_ALL) {
          Print (L"Variable Name: %s\n", VariableName);
          Print (L"GUID: ");
          Print (L"%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X\n",
                 TargetGuid.Data1, TargetGuid.Data2, TargetGuid.Data3,
                 TargetGuid.Data4[0], TargetGuid.Data4[1], TargetGuid.Data4[2],
                 TargetGuid.Data4[3], TargetGuid.Data4[4], TargetGuid.Data4[5],
                 TargetGuid.Data4[6], TargetGuid.Data4[7]);
          Print (L"Size: %d bytes\n", VariableSize);
          Print (L"Attributes: 0x%08X\n\n", Attributes);
          
          Print (L"Hexadecimal dump:\n");
          PrintHexDump (VariableData, VariableSize);
          
          Print (L"\nAs string (UCS-2): ");
          PrintUcsString (VariableData, VariableSize);
          
          Print (L"As string (ASCII): ");
          PrintAsciiString (VariableData, VariableSize);
        } else {
          // Выводим только в указанном формате
          switch (OutputType) {
            case OUTPUT_HEX:
              PrintHexDump (VariableData, VariableSize);
              break;
            case OUTPUT_ASCII:
              PrintAsciiString (VariableData, VariableSize);
              break;
            case OUTPUT_UCS:
              PrintUcsString (VariableData, VariableSize);
              break;
            default:
              break;
          }
        }
      }
    }
  }
  
  // Освобождаем память, если была выделена
  if (VariableData != NULL) {
    FreePool (VariableData);
  }
  
  if (!Found) {
    Print (L"Variable '%s' not found", VariableName);
    if (GuidSpecified) {
      Print (L" with specified GUID");
    }
    Print (L"\n");
    return EFI_NOT_FOUND;
  }
  
  return EFI_SUCCESS;
}

/**
  Перезагружает систему с загрузкой через BOOTx64.efi.
  
  @retval EFI_SUCCESS   Команда перезагрузки отправлена
  @retval другое        Ошибка при отправке команды перезагрузки
**/
EFI_STATUS
RebootToBoot (
  VOID
  )
{
  EFI_STATUS  Status;
  EFI_GUID    BootGuid = EFI_GLOBAL_VARIABLE;
  CHAR16      *BootFileName = L"\\EFI\\BOOT\\BOOTx64.EFI";
  CHAR16      *BootOptionName = L"SNSniffReboot";
  UINT16      BootOrder = 0;
  
  // Устанавливаем загрузочный вариант
  Status = gRT->SetVariable (
                  BootOptionName,
                  &BootGuid,
                  EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
                  StrSize (BootFileName),
                  BootFileName
                  );
                  
  if (EFI_ERROR (Status)) {
    Print (L"Error: Failed to set boot option\n");
    return Status;
  }
  
  // Устанавливаем порядок загрузки
  Status = gRT->SetVariable (
                  L"BootOrder",
                  &BootGuid,
                  EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
                  sizeof (UINT16),
                  &BootOrder
                  );
                  
  if (EFI_ERROR (Status)) {
    Print (L"Error: Failed to set boot order\n");
    return Status;
  }
  
  // Перезагружаем систему
  Print (L"Rebooting system to BOOTx64.efi...\n");
  gRT->ResetSystem (EfiResetWarm, EFI_SUCCESS, 0, NULL);
  
  return EFI_SUCCESS;
}

/**
  Запускает внешнюю EFI программу через прямую командную строку.
  
  @param AmideEfiPath   Путь к AMIDEEFIx64.efi
  @param SerialNumber   Серийный номер для прошивки
  
  @retval EFI_SUCCESS   Программа успешно выполнена
  @retval другое        Ошибка при запуске программы
**/
EFI_STATUS
RunAmideefi (
  IN CONST CHAR16    *AmideEfiPath,
  IN CONST CHAR16    *SerialNumber
  )
{
  CHAR16 CommandLine[MAX_BUFFER_SIZE];
  EFI_STATUS Status;
  
  // Проверяем существование файла
  if (ShellIsFile((CHAR16*)AmideEfiPath) != EFI_SUCCESS) {
    Print(L"Error: AMIDEEFIx64.efi not found at '%s'\n", AmideEfiPath);
    return EFI_NOT_FOUND;
  }
  
  // Формируем командную строку со всеми необходимыми параметрами
  ZeroMem(CommandLine, sizeof(CommandLine));
  UnicodeSPrint(CommandLine, sizeof(CommandLine), 
                L"%s /SS %s /BS %s", 
                AmideEfiPath, SerialNumber, SerialNumber);
  
  Print(L"Executing: %s\n", CommandLine);
  
  // Запускаем как отдельную команду через Shell
  Status = ShellExecute(&gImageHandle, CommandLine, TRUE, NULL, NULL);
  
  if (EFI_ERROR(Status)) {
    Print(L"Error: Failed to execute AMIDEEFIx64.efi: %r\n", Status);
  } else {
    Print(L"AMIDEEFIx64.efi executed successfully\n");
  }
  
  return Status;
}

EFI_STATUS
GetSmbiosString (
  IN  UINT8     StringNumber,
  IN  CHAR8     *StringTable,
  OUT CHAR16    *StringBuffer,
  IN  UINTN     StringBufferSize
  )
{
  UINTN i;

  if (StringNumber == 0 || StringTable == NULL || StringBuffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  // Пропускаем (StringNumber - 1) строк, каждая заканчивается нулевым байтом.
  for (i = 1; i < StringNumber; i++) {
    // Пропускаем символы текущей строки до нулевого байта.
    while (*StringTable != 0) {
      StringTable++;
    }
    // Переходим через нулевой байт.
    StringTable++;
    // Если мы достигли двойного нуля, строка не найдена.
    if (*StringTable == 0) {
      return EFI_NOT_FOUND;
    }
  }

  // Копируем найденную строку в выходной буфер с преобразованием в UCS-2.
  for (i = 0; i < StringBufferSize - 1 && StringTable[i] != 0; i++) {
    StringBuffer[i] = (CHAR16)StringTable[i];
  }
  StringBuffer[i] = 0;

  return EFI_SUCCESS;
}


/**
  Получает серийный номер системы из SMBIOS.
  
  @param SystemSerialNumber   Буфер для серийного номера системы
  @param BufferSize           Размер буфера
  
  @retval EFI_SUCCESS         Серийный номер успешно получен
  @retval другое              Ошибка при получении серийного номера
**/
EFI_STATUS
GetSystemSerialNumber (
  OUT CHAR16    *SystemSerialNumber,
  IN  UINTN     BufferSize
  )
{
  EFI_STATUS                Status;
  EFI_SMBIOS_PROTOCOL       *Smbios;
  EFI_SMBIOS_HANDLE         SmbiosHandle;
  EFI_SMBIOS_TABLE_HEADER   *Record;
  SMBIOS_TABLE_TYPE1        *Type1Record;
  CHAR8                     *StringTable;
  
  // Инициализируем выходной буфер
  ZeroMem (SystemSerialNumber, BufferSize * sizeof(CHAR16));
  
  // Получаем доступ к SMBIOS протоколу
  Status = gBS->LocateProtocol (
                &gEfiSmbiosProtocolGuid,
                NULL,
                (VOID **)&Smbios
                );
                
  if (EFI_ERROR (Status)) {
    Print (L"Error: Failed to locate SMBIOS protocol: %r\n", Status);
    return Status;
  }
  
  // Находим запись с информацией о системе (Type 1)
  SmbiosHandle = SMBIOS_HANDLE_PI_RESERVED;
  Status = Smbios->GetNext (Smbios, &SmbiosHandle, NULL, &Record, NULL);
  
  while (!EFI_ERROR (Status) && Record->Type != SMBIOS_TYPE_SYSTEM_INFORMATION) {
    Status = Smbios->GetNext (Smbios, &SmbiosHandle, NULL, &Record, NULL);
  }
  
  if (EFI_ERROR (Status)) {
    Print (L"Error: System Information record not found in SMBIOS: %r\n", Status);
    return Status;
  }
  
  // Получаем запись Type 1 (System Information)
  Type1Record = (SMBIOS_TABLE_TYPE1 *)Record;
  
  // Находим таблицу строк (она идет сразу после структуры)
  StringTable = (CHAR8 *)((UINT8 *)Type1Record + Type1Record->Hdr.Length);
  
  // Получаем строку с серийным номером
  Status = GetSmbiosString (
             Type1Record->SerialNumber,
             StringTable,
             SystemSerialNumber,
             BufferSize
             );
             
  if (EFI_ERROR (Status)) {
    Print (L"Error: Failed to get System Serial Number string: %r\n", Status);
    return Status;
  }
  
  return EFI_SUCCESS;
}

/**
  Получает серийный номер материнской платы из SMBIOS.
  
  @param BaseBoardSerialNumber  Буфер для серийного номера материнской платы
  @param BufferSize             Размер буфера
  
  @retval EFI_SUCCESS           Серийный номер успешно получен
  @retval другое                Ошибка при получении серийного номера
**/
EFI_STATUS
GetBaseBoardSerialNumber (
  OUT CHAR16    *BaseBoardSerialNumber,
  IN  UINTN     BufferSize
  )
{
  EFI_STATUS                Status;
  EFI_SMBIOS_PROTOCOL       *Smbios;
  EFI_SMBIOS_HANDLE         SmbiosHandle;
  EFI_SMBIOS_TABLE_HEADER   *Record;
  SMBIOS_TABLE_TYPE2        *Type2Record;
  CHAR8                     *StringTable;
  
  // Инициализируем выходной буфер
  ZeroMem (BaseBoardSerialNumber, BufferSize * sizeof(CHAR16));
  
  // Получаем доступ к SMBIOS протоколу
  Status = gBS->LocateProtocol (
                &gEfiSmbiosProtocolGuid,
                NULL,
                (VOID **)&Smbios
                );
                
  if (EFI_ERROR (Status)) {
    Print (L"Error: Failed to locate SMBIOS protocol: %r\n", Status);
    return Status;
  }
  
  // Находим запись с информацией о материнской плате (Type 2)
  SmbiosHandle = SMBIOS_HANDLE_PI_RESERVED;
  Status = Smbios->GetNext (Smbios, &SmbiosHandle, NULL, &Record, NULL);
  
  while (!EFI_ERROR (Status) && Record->Type != SMBIOS_TYPE_BASEBOARD_INFORMATION) {
    Status = Smbios->GetNext (Smbios, &SmbiosHandle, NULL, &Record, NULL);
  }
  
  if (EFI_ERROR (Status)) {
    Print (L"Error: Baseboard Information record not found in SMBIOS: %r\n", Status);
    return Status;
  }
  
  // Получаем запись Type 2 (Baseboard Information)
  Type2Record = (SMBIOS_TABLE_TYPE2 *)Record;
  
  // Находим таблицу строк (она идет сразу после структуры)
  StringTable = (CHAR8 *)((UINT8 *)Type2Record + Type2Record->Hdr.Length);
  
  // Получаем строку с серийным номером
  Status = GetSmbiosString (
             Type2Record->SerialNumber,
             StringTable,
             BaseBoardSerialNumber,
             BufferSize
             );
             
  if (EFI_ERROR (Status)) {
    Print (L"Error: Failed to get Baseboard Serial Number string: %r\n", Status);
    return Status;
  }
  
  return EFI_SUCCESS;
}

/**
  Выводит информацию о системе из SMBIOS Type 1 записи.
**/
VOID
PrintSystemInfo (
  VOID
  )
{
  EFI_STATUS                Status;
  EFI_SMBIOS_PROTOCOL       *Smbios;
  EFI_SMBIOS_HANDLE         SmbiosHandle;
  EFI_SMBIOS_TABLE_HEADER   *Record;
  SMBIOS_TABLE_TYPE1        *Type1Record;
  CHAR8                     *StringTable;
  CHAR16                    TempString[MAX_BUFFER_SIZE];
  
  // Получаем доступ к SMBIOS протоколу
  Status = gBS->LocateProtocol (
                &gEfiSmbiosProtocolGuid,
                NULL,
                (VOID **)&Smbios
                );
                
  if (EFI_ERROR (Status)) {
    return;
  }
  
  // Находим запись с информацией о системе (Type 1)
  SmbiosHandle = SMBIOS_HANDLE_PI_RESERVED;
  Status = Smbios->GetNext (Smbios, &SmbiosHandle, NULL, &Record, NULL);
  
  while (!EFI_ERROR (Status) && Record->Type != SMBIOS_TYPE_SYSTEM_INFORMATION) {
    Status = Smbios->GetNext (Smbios, &SmbiosHandle, NULL, &Record, NULL);
  }
  
  if (EFI_ERROR (Status)) {
    return;
  }
  
  // Получаем запись Type 1 (System Information)
  Type1Record = (SMBIOS_TABLE_TYPE1 *)Record;
  
  Print (L"\n===== System Information =====\n\n");
  
  // Находим таблицу строк (она идет сразу после структуры)
  StringTable = (CHAR8 *)((UINT8 *)Type1Record + Type1Record->Hdr.Length);
  
  // Выводим информацию о производителе
  if (Type1Record->Manufacturer != 0) {
    ZeroMem (TempString, sizeof(TempString));
    GetSmbiosString (Type1Record->Manufacturer, StringTable, TempString, MAX_BUFFER_SIZE);
    Print (L"Manufacturer: %s\n", TempString);
  } else {
    Print (L"Manufacturer: <Not Specified>\n");
  }
  
  // Выводим информацию о продукте
  if (Type1Record->ProductName != 0) {
    ZeroMem (TempString, sizeof(TempString));
    GetSmbiosString (Type1Record->ProductName, StringTable, TempString, MAX_BUFFER_SIZE);
    Print (L"Product Name: %s\n", TempString);
  } else {
    Print (L"Product Name: <Not Specified>\n");
  }
  
  // Выводим информацию о версии
  if (Type1Record->Version != 0) {
    ZeroMem (TempString, sizeof(TempString));
    GetSmbiosString (Type1Record->Version, StringTable, TempString, MAX_BUFFER_SIZE);
    Print (L"Version: %s\n", TempString);
  } else {
    Print (L"Version: <Not Specified>\n");
  }
  
  // Выводим серийный номер
  if (Type1Record->SerialNumber != 0) {
    ZeroMem (TempString, sizeof(TempString));
    GetSmbiosString (Type1Record->SerialNumber, StringTable, TempString, MAX_BUFFER_SIZE);
    Print (L"Serial Number: %s\n", TempString);
  } else {
    Print (L"Serial Number: <Not Specified>\n");
  }
  
  // Выводим UUID если он доступен
  if (!Type1Record->Uuid.Data1) {
    Print (L"UUID: <Not Specified>\n");
  } else {
    Print (L"UUID: %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X\n",
           Type1Record->Uuid.Data1, Type1Record->Uuid.Data2, Type1Record->Uuid.Data3,
           Type1Record->Uuid.Data4[0], Type1Record->Uuid.Data4[1], Type1Record->Uuid.Data4[2],
           Type1Record->Uuid.Data4[3], Type1Record->Uuid.Data4[4], Type1Record->Uuid.Data4[5],
           Type1Record->Uuid.Data4[6], Type1Record->Uuid.Data4[7]);
  }
}

/**
  Выводит подробную информацию о материнской плате из SMBIOS.
  
  @retval EFI_SUCCESS         Информация успешно выведена
  @retval другое              Ошибка при получении информации
**/
EFI_STATUS
DisplayBaseBoardInfo (
  VOID
  )
{
  EFI_STATUS                Status;
  EFI_SMBIOS_PROTOCOL       *Smbios;
  EFI_SMBIOS_HANDLE         SmbiosHandle;
  EFI_SMBIOS_TABLE_HEADER   *Record;
  SMBIOS_TABLE_TYPE2        *Type2Record;
  CHAR8                     *StringTable;
  CHAR16                    TempString[MAX_BUFFER_SIZE];
  
  // Получаем доступ к SMBIOS протоколу
  Status = gBS->LocateProtocol (
                &gEfiSmbiosProtocolGuid,
                NULL,
                (VOID **)&Smbios
                );
                
  if (EFI_ERROR (Status)) {
    Print (L"Error: Failed to locate SMBIOS protocol: %r\n", Status);
    return Status;
  }
  
  // Находим запись с информацией о материнской плате (Type 2)
  SmbiosHandle = SMBIOS_HANDLE_PI_RESERVED;
  Status = Smbios->GetNext (Smbios, &SmbiosHandle, NULL, &Record, NULL);
  
  while (!EFI_ERROR (Status) && Record->Type != SMBIOS_TYPE_BASEBOARD_INFORMATION) {
    Status = Smbios->GetNext (Smbios, &SmbiosHandle, NULL, &Record, NULL);
  }
  
  if (EFI_ERROR (Status)) {
    Print (L"Error: Baseboard Information record not found in SMBIOS: %r\n", Status);
    return Status;
  }
  
  // Получаем запись Type 2 (Baseboard Information)
  Type2Record = (SMBIOS_TABLE_TYPE2 *)Record;
  
  Print (L"\n===== Baseboard Information =====\n\n");
  
  // Находим таблицу строк (она идет сразу после структуры)
  StringTable = (CHAR8 *)((UINT8 *)Type2Record + Type2Record->Hdr.Length);
  
  // Выводим информацию о производителе
  if (Type2Record->Manufacturer != 0) {
    ZeroMem (TempString, sizeof(TempString));
    GetSmbiosString (Type2Record->Manufacturer, StringTable, TempString, MAX_BUFFER_SIZE);
    Print (L"Manufacturer: %s\n", TempString);
  } else {
    Print (L"Manufacturer: <Not Specified>\n");
  }
  
  // Выводим информацию о продукте
  if (Type2Record->ProductName != 0) {
    ZeroMem (TempString, sizeof(TempString));
    GetSmbiosString (Type2Record->ProductName, StringTable, TempString, MAX_BUFFER_SIZE);
    Print (L"Product Name: %s\n", TempString);
  } else {
    Print (L"Product Name: <Not Specified>\n");
  }
  
  // Выводим информацию о версии
  if (Type2Record->Version != 0) {
    ZeroMem (TempString, sizeof(TempString));
    GetSmbiosString (Type2Record->Version, StringTable, TempString, MAX_BUFFER_SIZE);
    Print (L"Version: %s\n", TempString);
  } else {
    Print (L"Version: <Not Specified>\n");
  }
  
  // Выводим серийный номер
  if (Type2Record->SerialNumber != 0) {
    ZeroMem (TempString, sizeof(TempString));
    GetSmbiosString (Type2Record->SerialNumber, StringTable, TempString, MAX_BUFFER_SIZE);
    Print (L"Serial Number: %s\n", TempString);
  } else {
    Print (L"Serial Number: <Not Specified>\n");
  }
  
  // Выводим тег актива
  if (Type2Record->AssetTag != 0) {
    ZeroMem (TempString, sizeof(TempString));
    GetSmbiosString (Type2Record->AssetTag, StringTable, TempString, MAX_BUFFER_SIZE);
    Print (L"Asset Tag: %s\n", TempString);
  } else {
    Print (L"Asset Tag: <Not Specified>\n");
  }
  
  // Выводим особенности платы
  Print (L"Feature Flags: 0x%02X\n", Type2Record->FeatureFlag);
  if (Type2Record->FeatureFlag.Motherboard)            Print(L"  - Hosting Board\n");
  if (Type2Record->FeatureFlag.RequiresDaughterCard)   Print(L"  - Requires Daughter Board\n");
  if (Type2Record->FeatureFlag.Removable)              Print(L"  - Removable\n");
  if (Type2Record->FeatureFlag.Replaceable)            Print(L"  - Replaceable\n");
  if (Type2Record->FeatureFlag.HotSwappable)           Print(L"  - Hot Swappable\n");


  
  // Выводим расположение в шасси
  if (Type2Record->LocationInChassis != 0) {
    ZeroMem (TempString, sizeof(TempString));
    GetSmbiosString (Type2Record->LocationInChassis, StringTable, TempString, MAX_BUFFER_SIZE);
    Print (L"Location in Chassis: %s\n", TempString);
  } else {
    Print (L"Location in Chassis: <Not Specified>\n");
  }
  
  // Выводим тип платы
  CONST CHAR16 *BoardTypes[] = {
    L"Unknown",
    L"Other",
    L"Server Blade",
    L"Connectivity Switch",
    L"System Management Module",
    L"Processor Module",
    L"I/O Module",
    L"Memory Module",
    L"Daughter Board",
    L"Motherboard",
    L"Processor/Memory Module",
    L"Processor/IO Module",
    L"Interconnect Board"
  };
  
  UINT8 BoardType = Type2Record->BoardType;
  if (BoardType < (sizeof(BoardTypes) / sizeof(BoardTypes[0]))) {
    Print (L"Board Type: %s\n", BoardTypes[BoardType]);
  } else {
    Print (L"Board Type: Unknown (%d)\n", BoardType);
  }
  
  // Выводим дополнительную информацию о системе из Type 1
  PrintSystemInfo();
  
  return EFI_SUCCESS;
}

/**
  Проверяет, совпадает ли серийный номер из указанной EFI переменной с 
  серийными номерами в SMBIOS информации.
  
  @param SerialVarName    Имя переменной UEFI с серийным номером
  @param SerialVarGuid    GUID переменной UEFI
  
  @retval TRUE            Серийный номер совпадает
  @retval FALSE           Серийный номер не совпадает или произошла ошибка
**/
BOOLEAN
CheckSerialNumber (
  IN  CONST CHAR16    *SerialVarName,
  IN  EFI_GUID        *SerialVarGuid
  )
{
  EFI_STATUS  Status;
  VOID        *SnVarData = NULL;
  UINTN       SnVarSize = 0;
  CHAR16      SnString[MAX_BUFFER_SIZE];
  CHAR16      SystemSn[MAX_BUFFER_SIZE];
  CHAR16      BaseBoardSn[MAX_BUFFER_SIZE];
  BOOLEAN     SnMatches = FALSE;
  
  // Получаем серийный номер из переменной UEFI
  Status = GetVariableData (
            SerialVarName,
            SerialVarGuid,
            &SnVarData,
            &SnVarSize
            );
            
  if (EFI_ERROR (Status)) {
    Print (L"Error: Failed to get Serial Number from variable '%s'\n", SerialVarName);
    return FALSE;
  }
  
  // Конвертируем данные в строку
  ZeroMem(SnString, sizeof(SnString));
  
  // Проверяем формат данных (UCS-2 или ASCII)
  if (SnVarSize >= 2 && ((CHAR16*)SnVarData)[SnVarSize/2 - 1] == 0) {
    // Данные в UCS-2 формате
    StrCpyS(SnString, MAX_BUFFER_SIZE, (CHAR16*)SnVarData);
  } else {
    // Предполагаем ASCII формат или бинарные данные, конвертируем в строку
    for (UINTN i = 0; i < MIN(SnVarSize, MAX_BUFFER_SIZE-1); i++) {
      SnString[i] = ((UINT8*)SnVarData)[i];
    }
    SnString[MIN(SnVarSize, MAX_BUFFER_SIZE-1)] = 0;
  }
  
  // Получаем серийный номер системы из SMBIOS
  Status = GetSystemSerialNumber(SystemSn, MAX_BUFFER_SIZE);
  if (!EFI_ERROR(Status)) {
    Print(L"System Serial Number from SMBIOS: %s\n", SystemSn);
    
    // Сравниваем с целевым серийным номером
    if (StrCmp(SystemSn, SnString) == 0) {
      Print(L"System Serial Number matches the target value.\n");
      SnMatches = TRUE;
    } else {
      Print(L"System Serial Number does NOT match the target value.\n");
    }
  } else {
    Print(L"Warning: Could not retrieve System Serial Number from SMBIOS.\n");
  }
  
  // Получаем серийный номер материнской платы из SMBIOS
  Status = GetBaseBoardSerialNumber(BaseBoardSn, MAX_BUFFER_SIZE);
  if (!EFI_ERROR(Status)) {
    Print(L"Baseboard Serial Number from SMBIOS: %s\n", BaseBoardSn);
    
    // Сравниваем с целевым серийным номером
    if (StrCmp(BaseBoardSn, SnString) == 0) {
      Print(L"Baseboard Serial Number matches the target value.\n");
      SnMatches = TRUE;
    } else {
      Print(L"Baseboard Serial Number does NOT match the target value.\n");
    }
  } else {
    Print(L"Warning: Could not retrieve Baseboard Serial Number from SMBIOS.\n");
  }
  
  if (SnVarData != NULL) {
    FreePool(SnVarData);
  }
  
  return SnMatches;
}

/**
  Проверяет серийный номер и MAC-адрес, перепрошивает при необходимости.
  
  @param Config    Указатель на конфигурацию проверки
  
  @retval EFI_SUCCESS   Проверка и/или перепрошивка успешно выполнены
  @retval другое        Ошибка при проверке или перепрошивке
**/
EFI_STATUS
CheckAndFlashValues (
  IN CHECK_CONFIG  *Config
  )
{
  EFI_STATUS  Status;
  VOID        *SnVarData = NULL;         // Данные из переменной SerialVarName
  UINTN       SnVarSize = 0;
  VOID        *MacVarData = NULL;        // Данные из переменной MacVarName
  UINTN       MacVarSize = 0;
  BOOLEAN     SnMatches = FALSE;
  BOOLEAN     MacMatches = FALSE;
  UINTN       RetryCount;
  CHAR16      SnString[MAX_BUFFER_SIZE]; // Строка с серийным номером
  
  if (Config->CheckOnly) {
    Print (L"Starting Serial Number and MAC verification (Check-Only Mode)...\n\n");
  } else {
    Print (L"Starting Serial Number and MAC verification...\n\n");
  }
  
  // Проверяем, нужно ли проверять серийный номер
  if (Config->CheckSn) {
    // Получаем серийный номер из переменной UEFI (который нужно прошить/проверить)
    Status = GetVariableData (
              Config->SerialVarName,
              Config->SerialVarGuid,
              &SnVarData,
              &SnVarSize
              );
              
    if (EFI_ERROR (Status)) {
      Print (L"Error: Failed to get Serial Number from variable '%s'\n", Config->SerialVarName);
      return Status;
    }
    
    // Конвертируем данные в строку для отображения и использования с AMIDEEFIx64.efi
    ZeroMem(SnString, sizeof(SnString));
    
    // Проверяем формат данных (UCS-2 или ASCII)
    if (SnVarSize >= 2 && ((CHAR16*)SnVarData)[SnVarSize/2 - 1] == 0) {
      // Данные в UCS-2 формате
      StrCpyS(SnString, MAX_BUFFER_SIZE, (CHAR16*)SnVarData);
    } else {
      // Предполагаем ASCII формат или бинарные данные, конвертируем в строку
      for (UINTN i = 0; i < MIN(SnVarSize, MAX_BUFFER_SIZE-1); i++) {
        SnString[i] = ((UINT8*)SnVarData)[i];
      }
      SnString[MIN(SnVarSize, MAX_BUFFER_SIZE-1)] = 0;
    }
    
    Print (L"Target Serial Number from EFI variable '%s': %s\n", 
           Config->SerialVarName, SnString);
    
    // Проверяем серийные номера в SMBIOS
    SnMatches = CheckSerialNumber(Config->SerialVarName, Config->SerialVarGuid);
  } else {
    // Если не проверяем SN, считаем его совпадающим
    SnMatches = TRUE;
    Print (L"Serial Number check skipped.\n");
  }
  
  // Проверяем, нужно ли проверять MAC-адрес
  if (Config->CheckMac) {
    // Получаем MAC-адрес из переменной UEFI
    Status = GetVariableData (
              Config->MacVarName,
              Config->MacVarGuid,
              &MacVarData,
              &MacVarSize
              );
              
    if (EFI_ERROR (Status)) {
      Print (L"Error: Failed to get MAC Address from variable '%s'\n", Config->MacVarName);
      
      // Если SN не прошит, то пытаемся его прошить независимо от MAC
      if (SnVarData != NULL) {
        if (!SnMatches && !Config->CheckOnly) {
          goto FlashSerial;
        }
      }
      
      if (SnVarData != NULL) {
        FreePool (SnVarData);
      }
      return Status;
    }
    
    // Здесь следует добавить код для проверки MAC-адресов сетевых интерфейсов
    // Поскольку это требует использования специфичных протоколов, оставим как заглушку
    Print (L"Target MAC Address from EFI variable: ");
    PrintUcsString (MacVarData, MacVarSize);
    Print (L"Warning: MAC Address checking is not implemented yet.\n");
    Print (L"Assuming MAC Address does not match for testing.\n");
    MacMatches = FALSE;
    
  } else {
    // Если не проверяем MAC, считаем его совпадающим
    MacMatches = TRUE;
    Print (L"MAC Address check skipped.\n");
  }
  
  // Если работаем в режиме только проверки, выводим результат и завершаем работу
  if (Config->CheckOnly) {
    Print (L"\n=== Check Results ===\n");
    if (Config->CheckSn) {
      Print (L"Serial Number: %s\n", SnMatches ? L"MATCH" : L"MISMATCH");
    }
    if (Config->CheckMac) {
      Print (L"MAC Address: %s\n", MacMatches ? L"MATCH" : L"MISMATCH");
    }
    
    if (SnVarData != NULL) {
      FreePool (SnVarData);
    }
    if (MacVarData != NULL) {
      FreePool (MacVarData);
    }
    
    return (SnMatches && MacMatches) ? EFI_SUCCESS : EFI_DEVICE_ERROR;
  }
  
FlashSerial:
  // Если оба значения совпадают, ничего не делаем
  if (SnMatches && MacMatches) {
    Print (L"\nSuccess: All values match the expected values.\n");
    if (SnVarData != NULL) {
      FreePool (SnVarData);
    }
    if (MacVarData != NULL) {
      FreePool (MacVarData);
    }
    return EFI_SUCCESS;
  }
  
  // Если серийный номер не совпадает, пытаемся его прошить
  if (!SnMatches && SnVarData != NULL) {
    Print (L"\nAttempting to flash Serial Number...\n");
    
    // Пытаемся перепрошить серийный номер до 3 раз
    for (RetryCount = 0; RetryCount < 3; RetryCount++) {
      Print (L"Flashing attempt %d...\n", RetryCount + 1);
      
      // Запускаем AMIDEEFIx64.efi через Shell
      Status = RunAmideefi(
                Config->AmideEfiPath,
                SnString
                );
                
      if (!EFI_ERROR (Status)) {
        // Проверяем, был ли серийный номер прошит успешно
        BOOLEAN NewSnMatches = CheckSerialNumber(Config->SerialVarName, Config->SerialVarGuid);
        
        if (NewSnMatches) {
          Print (L"Serial Number was successfully flashed!\n");
          
          // Если MAC не совпадает, нужно перезагрузиться в систему
          if (!MacMatches) {
            Print (L"\nMAC Address needs to be updated. Rebooting to system for further updates...\n");
            if (SnVarData != NULL) {
              FreePool (SnVarData);
            }
            if (MacVarData != NULL) {
              FreePool (MacVarData);
            }
            return RebootToBoot();
          }
          
          if (SnVarData != NULL) {
            FreePool (SnVarData);
          }
          if (MacVarData != NULL) {
            FreePool (MacVarData);
          }
          return EFI_SUCCESS;
        }
        
        Print (L"Failed to verify flashed Serial Number. Retrying...\n");
      } else {
        Print (L"Failed to run AMIDEEFIx64.efi. Error: %r\n", Status);
      }
    }
    
    // Не удалось прошить серийный номер после 3 попыток
    Print (L"\nCRITICAL ERROR: Failed to flash Serial Number after 3 attempts!\n");
    if (SnVarData != NULL) {
      FreePool (SnVarData);
    }
    if (MacVarData != NULL) {
      FreePool (MacVarData);
    }
    return EFI_DEVICE_ERROR;
  }
  
  // Если только MAC-адрес не совпадает, но SN уже прошит
  if (SnMatches && !MacMatches) {
    Print (L"\nSerial Number is correct, but MAC Address needs to be updated.\n");
    Print (L"Rebooting to system for MAC Address update...\n");
    if (SnVarData != NULL) {
      FreePool (SnVarData);
    }
    if (MacVarData != NULL) {
      FreePool (MacVarData);
    }
    return RebootToBoot();
  }
  
  if (SnVarData != NULL) {
    FreePool (SnVarData);
  }
  if (MacVarData != NULL) {
    FreePool (MacVarData);
  }
  return EFI_SUCCESS;
}

/**
  Функция вывода справки по использованию.
**/
VOID
PrintUsage (
  VOID
  )
{
  Print (L"SNSniff - UEFI Serial Number and MAC Address Tool\n");
  Print (L"Usage: snsniff [variable_name] [options]\n\n");
  Print (L"Standard Options:\n");
  Print (L"  --guid GUID      : Specify GUID prefix or full GUID\n");
  Print (L"  --rawtype TYPE   : Output only in specified format (hex, ascii, ucs)\n\n");
  
  Print (L"Verification and Flashing Options:\n");
  Print (L"  --check          : Verify and flash if needed the SN and MAC\n");
  Print (L"  --check-only     : Verify but DO NOT flash SN and MAC (just report status)\n");
  Print (L"  --vsn VARNAME    : Name of EFI variable containing the serial number to flash\n");
  Print (L"  --vmac VARNAME   : Name of EFI variable containing the MAC address to check\n");
  Print (L"  --amid PATH      : Path to AMIDEEFIx64.efi (default: current directory)\n\n");
  
  Print (L"System Information:\n");
  Print (L"  --board-info     : Display detailed information about the motherboard\n\n");
  
  Print (L"Examples:\n");
  Print (L"  snsniff SerialNumber\n");
  Print (L"  snsniff SerialNumber --guid 12345678\n");
  Print (L"  snsniff --check --vsn SerialToFlash --vmac MacToCheck\n");
  Print (L"  snsniff --check-only --vsn SerialToFlash\n");
  Print (L"  snsniff --board-info\n");
}

/**
  Точка входа в приложение из Shell.

  @param[in] Argc    Количество аргументов.
  @param[in] Argv    Массив строк аргументов.

  @retval INTN       Код возврата.
**/
INTN
EFIAPI
ShellAppMain (
  IN UINTN  Argc,
  IN CHAR16 **Argv
  )
{
  EFI_STATUS   Status;
  CONST CHAR16 *VariableName = L"SerialNumber";
  CONST CHAR16 *GuidPrefix = NULL;
  OUTPUT_TYPE  OutputType = OUTPUT_ALL;
  UINTN        Index;
  BOOLEAN      CheckMode = FALSE;
  BOOLEAN      CheckOnlyMode = FALSE;  // Флаг для режима только проверки
  BOOLEAN      BoardInfoMode = FALSE;  // Флаг для вывода информации о плате
  CHECK_CONFIG Config;
  EFI_GUID     DefaultGuid = mCustomVarGuid;
  
  // Очищаем экран
  gST->ConOut->ClearScreen (gST->ConOut);
  
  // Инициализируем конфигурацию проверки
  ZeroMem (&Config, sizeof (CHECK_CONFIG));
  Config.SerialVarName = NULL;  // По умолчанию не задано
  Config.MacVarName = NULL;     // По умолчанию не задано
  Config.AmideEfiPath = L"AMIDEEFIx64.efi";
  Config.SerialVarGuid = &DefaultGuid;
  Config.MacVarGuid = &DefaultGuid;
  Config.CheckSn = FALSE;
  Config.CheckMac = FALSE;
  Config.CheckOnly = FALSE;
  
  // Проверяем аргументы командной строки
  if (Argc == 1) {
    // Нет аргументов, используем значения по умолчанию
    PrintUsage();
    Print (L"\nUsing default values...\n\n");
  } else {
    // Первый аргумент - имя переменной (если не опция)
    if (Argv[1][0] != L'-') {
      VariableName = Argv[1];
    }
    
    // Обрабатываем остальные аргументы
    for (Index = 1; Index < Argc; Index++) {
      if (StrCmp (Argv[Index], L"--help") == 0 || StrCmp (Argv[Index], L"-h") == 0) {
        PrintUsage();
        return EFI_SUCCESS;
      } else if (StrCmp (Argv[Index], L"--guid") == 0) {
        // Проверяем, что есть следующий аргумент
        if (Index + 1 < Argc) {
          GuidPrefix = Argv[Index + 1];
          Index++; // Пропускаем значение опции
        } else {
          Print (L"Error: Missing GUID value\n");
          PrintUsage();
          return EFI_INVALID_PARAMETER;
        }
      } else if (StrCmp (Argv[Index], L"--rawtype") == 0) {
        // Проверяем, что есть следующий аргумент
        if (Index + 1 < Argc) {
          if (StrCmp (Argv[Index + 1], L"hex") == 0) {
            OutputType = OUTPUT_HEX;
          } else if (StrCmp (Argv[Index + 1], L"ascii") == 0) {
            OutputType = OUTPUT_ASCII;
          } else if (StrCmp (Argv[Index + 1], L"ucs") == 0) {
            OutputType = OUTPUT_UCS;
          } else {
            Print (L"Error: Invalid rawtype value. Must be 'hex', 'ascii', or 'ucs'\n");
            PrintUsage();
            return EFI_INVALID_PARAMETER;
          }
          Index++; // Пропускаем значение опции
        } else {
          Print (L"Error: Missing rawtype value\n");
          PrintUsage();
          return EFI_INVALID_PARAMETER;
        }
      } else if (StrCmp (Argv[Index], L"--check") == 0) {
        // Включаем режим проверки и перепрошивки
        CheckMode = TRUE;
      } else if (StrCmp (Argv[Index], L"--check-only") == 0) {
        // Включаем режим только проверки
        CheckOnlyMode = TRUE;
      } else if (StrCmp (Argv[Index], L"--board-info") == 0) {
        // Включаем режим вывода информации о материнской плате
        BoardInfoMode = TRUE;
      } else if (StrCmp (Argv[Index], L"--vsn") == 0) {
        // Проверяем, что есть следующий аргумент
        if (Index + 1 < Argc) {
          Config.SerialVarName = Argv[Index + 1];
          Config.CheckSn = TRUE;
          Index++; // Пропускаем значение опции
        } else {
          Print (L"Error: Missing serial variable name\n");
          PrintUsage();
          return EFI_INVALID_PARAMETER;
        }
      } else if (StrCmp (Argv[Index], L"--vmac") == 0) {
        // Проверяем, что есть следующий аргумент
        if (Index + 1 < Argc) {
          Config.MacVarName = Argv[Index + 1];
          Config.CheckMac = TRUE;
          Index++; // Пропускаем значение опции
        } else {
          Print (L"Error: Missing MAC variable name\n");
          PrintUsage();
          return EFI_INVALID_PARAMETER;
        }
      } else if (StrCmp (Argv[Index], L"--amid") == 0) {
        // Проверяем, что есть следующий аргумент
        if (Index + 1 < Argc) {
          Config.AmideEfiPath = Argv[Index + 1];
          Index++; // Пропускаем значение опции
        } else {
          Print (L"Error: Missing AMIDE EFI path\n");
          PrintUsage();
          return EFI_INVALID_PARAMETER;
        }
      }
    }
  }
  
  // Если указан GUID, пытаемся его распарсить
  if (GuidPrefix != NULL) {
    EFI_GUID TempGuid;
    if (ParseGuidPrefix (GuidPrefix, &TempGuid)) {
      Config.SerialVarGuid = &TempGuid;
      Config.MacVarGuid = &TempGuid;
    }
  }
  
  // Режим вывода информации о материнской плате
  if (BoardInfoMode) {
    Status = DisplayBaseBoardInfo();
    return (INTN)Status;
  }
  
  // Режим проверки (с прошивкой или без)
  if (CheckMode || CheckOnlyMode) {
    // Режим проверки и перепрошивки или только проверки
    if (!Config.CheckSn && !Config.CheckMac) {
      Print (L"Error: You must specify at least one value to check (--vsn or --vmac)\n");
      PrintUsage();
      return EFI_INVALID_PARAMETER;
    }
    
    // Устанавливаем флаг CheckOnly для передачи в CheckAndFlashValues
    Config.CheckOnly = CheckOnlyMode;
    
    // Проверяем и перепрошиваем значения (если не CheckOnlyMode)
    Status = CheckAndFlashValues (&Config);
  } else {
    // Стандартный режим - просто отображаем переменную
    Status = FindAndPrintVariable (VariableName, GuidPrefix, OutputType);
  }
  
  // Ждем нажатия клавиши, если не используется rawtype
  if (OutputType == OUTPUT_ALL) {
    EFI_INPUT_KEY Key;
    Print (L"\nPress any key to exit...\n");
    gBS->WaitForEvent (1, &gST->ConIn->WaitForKey, NULL);
    gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);
  }
  
  return (INTN)Status;
}

/**
  Точка входа для UEFI приложения.

  @param[in] ImageHandle    Хендл образа.
  @param[in] SystemTable    Указатель на системную таблицу.

  @retval EFI_SUCCESS       Приложение выполнилось успешно.
**/
EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;
  
  // Инициализируем библиотеки Shell для обработки аргументов
  Status = ShellInitialize();
  if (EFI_ERROR(Status)) {
    Print(L"Error: Failed to initialize Shell libraries\n");
    return Status;
  }
  
  // Проверяем, доступен ли протокол параметров Shell
  if (gEfiShellParametersProtocol == NULL) {
    Print(L"Error: Shell Parameters Protocol is not available\n");
    return EFI_NOT_FOUND;
  }
  
  // Вызываем основную функцию приложения, которая обрабатывает аргументы
  return (EFI_STATUS)ShellAppMain(gEfiShellParametersProtocol->Argc,
                                  gEfiShellParametersProtocol->Argv);
}