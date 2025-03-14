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
#include <Protocol/SimpleNetwork.h>

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
  BOOLEAN   PowerDown;              // Флаг выключения/перезагрузки системы
  EFI_GUID  *SerialVarGuid;         // GUID для переменной с серийным номером
  EFI_GUID  *MacVarGuid;            // GUID для переменной с MAC-адресом
} CHECK_CONFIG;

// Прототипы функций
EFI_STATUS
RebootToBoot (
  VOID
  );

EFI_STATUS
PowerDownSystem (
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
  Если VariableGuid равен NULL, ищет переменную по всем доступным GUID.

  @param VariableName   Имя переменной
  @param VariableGuid   GUID переменной (может быть NULL для поиска по всем GUID)
  @param VariableData   Указатель на буфер для данных (будет выделен)
  @param VariableSize   Указатель на размер данных
  @param FoundGuid      Указатель на буфер для найденного GUID (может быть NULL)

  @retval EFI_SUCCESS   Переменная успешно прочитана
  @retval другое        Ошибка при чтении переменной
**/
EFI_STATUS
GetVariableData (
  IN  CONST CHAR16    *VariableName,
  IN  EFI_GUID        *VariableGuid,
  OUT VOID            **VariableData,
  OUT UINTN           *VariableSize,
  OUT EFI_GUID        *FoundGuid OPTIONAL
  )
{
  EFI_STATUS  Status;
  UINT32      Attributes = 0;
  UINTN       Index;
  CHAR16      *Name = NULL;
  UINTN       NameSize = 256 * sizeof(CHAR16);
  EFI_GUID    TempGuid;
  BOOLEAN     Found = FALSE;
  
  // Проверяем входные параметры
  if (VariableName == NULL || VariableData == NULL || VariableSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  // Инициализируем выходные параметры
  *VariableData = NULL;
  *VariableSize = 0;
  
  // Если GUID указан, ищем только по нему
  if (VariableGuid != NULL) {
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
      } else if (FoundGuid != NULL) {
        CopyMem(FoundGuid, VariableGuid, sizeof(EFI_GUID));
      }
    }
    
    return Status;
  }
  
  // Если GUID не указан, сначала ищем по известным GUID
  for (Index = 0; mKnownGuids[Index].Guid != NULL && !Found; Index++) {
    // Получаем размер переменной
    Status = gRT->GetVariable (
                    (CHAR16*)VariableName,
                    mKnownGuids[Index].Guid,
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
                      mKnownGuids[Index].Guid,
                      &Attributes,
                      VariableSize,
                      *VariableData
                      );
                      
      if (!EFI_ERROR (Status)) {
        Found = TRUE;
        if (FoundGuid != NULL) {
          CopyMem(FoundGuid, mKnownGuids[Index].Guid, sizeof(EFI_GUID));
        }
      } else {
        FreePool (*VariableData);
        *VariableData = NULL;
        *VariableSize = 0;
      }
    }
  }
  
  // Если не нашли в известных GUID, перебираем все GUID в системе
  if (!Found) {
    // Выделяем буфер для имени переменной
    Name = AllocateZeroPool (NameSize);
    if (Name == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }
    
    // Инициализируем переменные для начала поиска
    ZeroMem (&TempGuid, sizeof (EFI_GUID));
    Name[0] = 0;
    
    // Перебираем все переменные в системе
    while (!Found) {
      NameSize = 256 * sizeof(CHAR16);  // Восстанавливаем размер буфера
      Status = gRT->GetNextVariableName (&NameSize, Name, &TempGuid);
      
      if (Status == EFI_BUFFER_TOO_SMALL) {
        // Буфер слишком мал, увеличиваем его размер
        FreePool (Name);
        Name = AllocateZeroPool (NameSize);
        if (Name == NULL) {
          return EFI_OUT_OF_RESOURCES;
        }
        
        // Повторяем попытку с увеличенным буфером
        Status = gRT->GetNextVariableName (&NameSize, Name, &TempGuid);
      }
      
      if (EFI_ERROR (Status)) {
        if (Status == EFI_NOT_FOUND) {
          // Больше переменных нет, завершаем поиск
          Status = EFI_NOT_FOUND;
          break;
        } else {
          // Другая ошибка
          break;
        }
      }
      
      // Проверяем, совпадает ли имя с искомым
      if (StrCmp (Name, VariableName) == 0) {
        // Нашли переменную с нужным именем, получаем ее значение
        *VariableSize = 0;
        Status = gRT->GetVariable (Name, &TempGuid, &Attributes, VariableSize, NULL);
        
        if (Status == EFI_BUFFER_TOO_SMALL) {
          // Выделяем память под данные
          *VariableData = AllocateZeroPool (*VariableSize);
          if (*VariableData == NULL) {
            FreePool (Name);
            return EFI_OUT_OF_RESOURCES;
          }
          
          // Получаем значение переменной
          Status = gRT->GetVariable (Name, &TempGuid, &Attributes, VariableSize, *VariableData);
          
          if (!EFI_ERROR (Status)) {
            Found = TRUE;
            if (FoundGuid != NULL) {
              CopyMem(FoundGuid, &TempGuid, sizeof(EFI_GUID));
            }
            break; // Нашли переменную, выходим из цикла
          } else {
            FreePool (*VariableData);
            *VariableData = NULL;
            *VariableSize = 0;
          }
        }
      }
    }
    
    // Освобождаем память, выделенную для имени
    if (Name != NULL) {
      FreePool (Name);
    }
  }
  
  if (!Found) {
    return EFI_NOT_FOUND;
  }
  
  return EFI_SUCCESS;
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
  EFI_GUID    FoundGuid;
  
  // Если указан префикс GUID, пытаемся его распарсить
  if (GuidPrefix != NULL && StrLen (GuidPrefix) > 0) {
    GuidSpecified = ParseGuidPrefix (GuidPrefix, &TargetGuid);
    if (!GuidSpecified) {
      Print (L"Error: Invalid GUID prefix '%s'\n", GuidPrefix);
      return EFI_INVALID_PARAMETER;
    }
  }
  
  // Если GUID не указан, ищем переменную по всем доступным GUID
  if (!GuidSpecified) {
    Status = GetVariableData(
              VariableName,
              NULL,  // Ищем по всем GUID
              &VariableData,
              &VariableSize,
              &FoundGuid
              );
              
    if (!EFI_ERROR(Status)) {
      Found = TRUE;
      
      // Проверяем, есть ли это GUID в известных GUID для более дружественного отображения
      CHAR16 *GuidName = L"Unknown";
      for (Index = 0; mKnownGuids[Index].Guid != NULL; Index++) {
        if (CompareGuid (mKnownGuids[Index].Guid, &FoundGuid)) {
          GuidName = mKnownGuids[Index].Name;
          break;
        }
      }
      
      // Если режим вывода не "только данные", выводим информацию о переменной
      if (OutputType == OUTPUT_ALL) {
        Print (L"Variable Name: %s\n", VariableName);
        Print (L"GUID: %s (%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X)\n", 
               GuidName,
               FoundGuid.Data1, FoundGuid.Data2, FoundGuid.Data3,
               FoundGuid.Data4[0], FoundGuid.Data4[1], FoundGuid.Data4[2],
               FoundGuid.Data4[3], FoundGuid.Data4[4], FoundGuid.Data4[5],
               FoundGuid.Data4[6], FoundGuid.Data4[7]);
        
        // Получаем атрибуты переменной
        gRT->GetVariable(
               (CHAR16*)VariableName,
               &FoundGuid,
               &Attributes,
               &VariableSize,
               VariableData
               );
        
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
  } else {
    // Ищем по указанному GUID
    Status = GetVariableData(
              VariableName,
              &TargetGuid,
              &VariableData,
              &VariableSize,
              NULL
              );
              
    if (!EFI_ERROR(Status)) {
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
        
        // Получаем атрибуты переменной
        gRT->GetVariable(
               (CHAR16*)VariableName,
               &TargetGuid,
               &Attributes,
               &VariableSize,
               VariableData
               );
        
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
  Ожидает нажатия клавиши перед перезагрузкой.
  
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
  EFI_INPUT_KEY Key;
  
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
  
  // Ждем нажатия клавиши перед перезагрузкой
  Print (L"Press any key to reboot to BOOTx64.efi...\n");
  gBS->WaitForEvent (1, &gST->ConIn->WaitForKey, NULL);
  gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);
  
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
  Сравнивает два MAC-адреса в формате ASCII строк с учетом разных форматов.
  
  @param Mac1     Первый MAC-адрес
  @param Mac2     Второй MAC-адрес
  
  @retval TRUE    MAC-адреса совпадают
  @retval FALSE   MAC-адреса не совпадают
**/
BOOLEAN
CompareMacAddresses (
  IN CONST CHAR8  *Mac1,
  IN CONST CHAR8  *Mac2
  )
{
  UINT8 BinaryMac1[6] = {0};
  UINT8 BinaryMac2[6] = {0};
  CHAR8 NormalizedMac1[13] = {0}; // 12 hex chars + null terminator
  CHAR8 NormalizedMac2[13] = {0}; // 12 hex chars + null terminator
  UINTN Mac1Len, Mac2Len;
  UINTN Index, OutIndex;
  
  if (Mac1 == NULL || Mac2 == NULL) {
    return FALSE;
  }
  
  Mac1Len = AsciiStrLen(Mac1);
  Mac2Len = AsciiStrLen(Mac2);
  
  // Нормализация первого MAC - удаляем разделители и преобразуем в верхний регистр
  OutIndex = 0;
  for (Index = 0; Index < Mac1Len && OutIndex < 12; Index++) {
    // Пропускаем разделители и пробелы
    if (Mac1[Index] == ':' || Mac1[Index] == '-' || Mac1[Index] == ' ' || Mac1[Index] == '.') {
      continue;
    }
    
    // Преобразуем строчные буквы в заглавные
    if (Mac1[Index] >= 'a' && Mac1[Index] <= 'f') {
      NormalizedMac1[OutIndex++] = Mac1[Index] - ('a' - 'A');
    } else {
      NormalizedMac1[OutIndex++] = Mac1[Index];
    }
  }
  NormalizedMac1[OutIndex] = '\0';
  
  // Нормализация второго MAC - удаляем разделители и преобразуем в верхний регистр
  OutIndex = 0;
  for (Index = 0; Index < Mac2Len && OutIndex < 12; Index++) {
    // Пропускаем разделители и пробелы
    if (Mac2[Index] == ':' || Mac2[Index] == '-' || Mac2[Index] == ' ' || Mac2[Index] == '.') {
      continue;
    }
    
    // Преобразуем строчные буквы в заглавные
    if (Mac2[Index] >= 'a' && Mac2[Index] <= 'f') {
      NormalizedMac2[OutIndex++] = Mac2[Index] - ('a' - 'A');
    } else {
      NormalizedMac2[OutIndex++] = Mac2[Index];
    }
  }
  NormalizedMac2[OutIndex] = '\0';
  
  // Если нормализованные строки имеют по 12 символов (6 байт MAC), сравниваем их
  if (AsciiStrLen(NormalizedMac1) == 12 && AsciiStrLen(NormalizedMac2) == 12) {
    // Для отладки
    Print(L"Normalized MAC 1: %a\n", NormalizedMac1);
    Print(L"Normalized MAC 2: %a\n", NormalizedMac2);
    
    return (AsciiStrnCmp(NormalizedMac1, NormalizedMac2, 12) == 0);
  }
  
  // Если нормализация не сработала, попробуем преобразовать их в бинарный формат
  // и затем сравнить
  
  // Преобразуем нормализованный первый MAC в бинарный формат
  if (AsciiStrLen(NormalizedMac1) == 12) {
    for (Index = 0; Index < 6; Index++) {
      CHAR8 HexByte[3] = {NormalizedMac1[Index*2], NormalizedMac1[Index*2+1], '\0'};
      UINT8 Value = 0;
      
      // Первый символ
      if (HexByte[0] >= '0' && HexByte[0] <= '9') {
        Value = (HexByte[0] - '0') << 4;
      } else if (HexByte[0] >= 'A' && HexByte[0] <= 'F') {
        Value = (HexByte[0] - 'A' + 10) << 4;
      } else {
        return FALSE; // Некорректный символ
      }
      
      // Второй символ
      if (HexByte[1] >= '0' && HexByte[1] <= '9') {
        Value |= (HexByte[1] - '0');
      } else if (HexByte[1] >= 'A' && HexByte[1] <= 'F') {
        Value |= (HexByte[1] - 'A' + 10);
      } else {
        return FALSE; // Некорректный символ
      }
      
      BinaryMac1[Index] = Value;
    }
  }
  
  // Преобразуем нормализованный второй MAC в бинарный формат
  if (AsciiStrLen(NormalizedMac2) == 12) {
    for (Index = 0; Index < 6; Index++) {
      CHAR8 HexByte[3] = {NormalizedMac2[Index*2], NormalizedMac2[Index*2+1], '\0'};
      UINT8 Value = 0;
      
      // Первый символ
      if (HexByte[0] >= '0' && HexByte[0] <= '9') {
        Value = (HexByte[0] - '0') << 4;
      } else if (HexByte[0] >= 'A' && HexByte[0] <= 'F') {
        Value = (HexByte[0] - 'A' + 10) << 4;
      } else {
        return FALSE; // Некорректный символ
      }
      
      // Второй символ
      if (HexByte[1] >= '0' && HexByte[1] <= '9') {
        Value |= (HexByte[1] - '0');
      } else if (HexByte[1] >= 'A' && HexByte[1] <= 'F') {
        Value |= (HexByte[1] - 'A' + 10);
      } else {
        return FALSE; // Некорректный символ
      }
      
      BinaryMac2[Index] = Value;
    }
  }
  
  // Для отладки
  if (AsciiStrLen(NormalizedMac1) == 12 && AsciiStrLen(NormalizedMac2) == 12) {
    Print(L"Binary MAC 1: %02X:%02X:%02X:%02X:%02X:%02X\n",
          BinaryMac1[0], BinaryMac1[1], BinaryMac1[2],
          BinaryMac1[3], BinaryMac1[4], BinaryMac1[5]);
    Print(L"Binary MAC 2: %02X:%02X:%02X:%02X:%02X:%02X\n",
          BinaryMac2[0], BinaryMac2[1], BinaryMac2[2],
          BinaryMac2[3], BinaryMac2[4], BinaryMac2[5]);
  }
  
  // Сравниваем бинарные MAC-адреса
  return (CompareMem(BinaryMac1, BinaryMac2, 6) == 0);
}

/**
  Преобразует бинарный MAC-адрес в строку формата XX:XX:XX:XX:XX:XX.
  
  @param MacAddr       Указатель на бинарный MAC-адрес (6 байт)
  @param MacAddrStr    Буфер для строки (минимум 18 байт)
**/
VOID
FormatMacAddress (
  IN  UINT8   *MacAddr,
  OUT CHAR8   *MacAddrStr
  )
{
  if (MacAddr == NULL || MacAddrStr == NULL) {
    return;
  }
  
  AsciiSPrint(
    MacAddrStr,
    18, // 17 символов + нулевой байт
    "%02X:%02X:%02X:%02X:%02X:%02X",
    MacAddr[0], MacAddr[1], MacAddr[2],
    MacAddr[3], MacAddr[4], MacAddr[5]
  );
}

/**
  Получает MAC-адрес из переменной UEFI и преобразует его в ASCII формат.
  
  @param VariableName    Имя переменной UEFI с MAC-адресом
  @param VariableGuid    GUID переменной UEFI (может быть NULL для поиска по всем GUID)
  @param MacString       Буфер для MAC-адреса в ASCII формате
  @param MacStringSize   Размер буфера
  @param FoundGuid       Указатель на буфер для найденного GUID (может быть NULL)
  
  @retval EFI_SUCCESS    MAC-адрес успешно получен и преобразован
  @retval другое         Ошибка при получении или преобразовании
**/
EFI_STATUS
GetMacAddressAsAscii (
  IN  CONST CHAR16    *VariableName,
  IN  EFI_GUID        *VariableGuid,
  OUT CHAR8           *MacString,
  IN  UINTN           MacStringSize,
  OUT EFI_GUID        *FoundGuid OPTIONAL
  )
{
  EFI_STATUS  Status;
  VOID        *MacData = NULL;
  UINTN       MacDataSize = 0;
  UINTN       StringLen = 0;
  UINTN       Index;
  
  // Проверяем входные параметры
  if (VariableName == NULL || MacString == NULL || MacStringSize == 0) {
    return EFI_INVALID_PARAMETER;
  }
  
  // Инициализируем выходной буфер
  ZeroMem (MacString, MacStringSize);
  
  // Получаем данные MAC-адреса из переменной UEFI
  Status = GetVariableData (
            VariableName,
            VariableGuid,
            &MacData,
            &MacDataSize,
            FoundGuid
            );
            
  if (EFI_ERROR (Status)) {
    return Status;
  }
  
  Print(L"DEBUG: MAC variable size: %d bytes\n", MacDataSize);
  Print(L"DEBUG: MAC variable raw data: ");
  for (Index = 0; Index < MIN(MacDataSize, 20); Index++) {
    Print(L"%02X ", ((UINT8*)MacData)[Index]);
  }
  Print(L"\n");
  
  // Проверяем размер данных для разных форматов
  if (MacDataSize == 6) {
    // Бинарный MAC-адрес (6 байт)
    Print(L"DEBUG: Detected binary MAC format (6 bytes)\n");
    FormatMacAddress((UINT8*)MacData, MacString);
  } else if (MacDataSize >= 2 && ((CHAR16*)MacData)[MacDataSize/2 - 1] == 0) {
    // Данные в UCS-2 формате, конвертируем в ASCII
    Print(L"DEBUG: Detected UCS-2 string format\n");
    CHAR16 *UnicodeData = (CHAR16*)MacData;
    StringLen = StrLen(UnicodeData);
    
    Print(L"DEBUG: UCS-2 MAC string: %s\n", UnicodeData);
    
    // Проверяем, что буфер достаточного размера
    if (StringLen >= MacStringSize) {
      StringLen = MacStringSize - 1;
    }
    
    // Конвертируем Unicode в ASCII
    for (Index = 0; Index < StringLen; Index++) {
      MacString[Index] = (CHAR8)UnicodeData[Index];
    }
    MacString[StringLen] = '\0';
  } else {
    // Предполагаем, что данные уже в ASCII формате
    Print(L"DEBUG: Assuming ASCII string format\n");
    StringLen = MacDataSize < MacStringSize ? MacDataSize : MacStringSize - 1;
    
    // Если последний байт равен 0, это может быть ASCII строка с нулевым завершением
    if (MacDataSize > 0 && ((UINT8*)MacData)[MacDataSize-1] == 0) {
      // Это ASCII строка с нулевым завершением, копируем её
      AsciiStrCpyS(MacString, MacStringSize, (CHAR8*)MacData);
      Print(L"DEBUG: Found null-terminated ASCII string\n");
    } else {
      // Копируем данные как есть
      CopyMem(MacString, MacData, StringLen);
      MacString[StringLen] = '\0';
    }
  }
  
  Print(L"DEBUG: Final ASCII MAC string: %a\n", MacString);
  
  // Проверяем, что получившаяся строка является валидным MAC-адресом
  // и добавляем разделители, если их нет
  if (AsciiStrLen(MacString) == 12) {
    // Формат без разделителей (AABBCCDDEEFF), преобразуем в формат с разделителями
    CHAR8 TempMacString[18];
    
    // Проверяем, что все символы являются шестнадцатеричными
    for (Index = 0; Index < 12; Index++) {
      if (!((MacString[Index] >= '0' && MacString[Index] <= '9') ||
            (MacString[Index] >= 'A' && MacString[Index] <= 'F') ||
            (MacString[Index] >= 'a' && MacString[Index] <= 'f'))) {
        break;
      }
    }
    
    // Если все символы шестнадцатеричные, форматируем строку
    if (Index == 12) {
      AsciiSPrint(
        TempMacString,
        sizeof(TempMacString),
        "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",
        MacString[0], MacString[1], MacString[2], MacString[3],
        MacString[4], MacString[5], MacString[6], MacString[7],
        MacString[8], MacString[9], MacString[10], MacString[11]
      );
      
      AsciiStrCpyS(MacString, MacStringSize, TempMacString);
      Print(L"DEBUG: Reformatted MAC with separators: %a\n", MacString);
    }
  }
  
  // Освобождаем память
  if (MacData != NULL) {
    FreePool (MacData);
  }
  
  return EFI_SUCCESS;
}

/**
  Выводит MAC-адрес в читаемом формате.
  
  @param MacAddr  Указатель на строку с MAC-адресом
**/
VOID
PrintMacAddress (
  IN CONST CHAR8  *MacAddr
  )
{
  // Проверяем входной параметр
  if (MacAddr == NULL) {
    Print (L"<Invalid MAC Address>\n");
    return;
  }
  
  // Выводим MAC-адрес, преобразуя ASCII в CHAR16 для Print
  UINTN i;
  for (i = 0; MacAddr[i] != '\0' && i < 100; i++) {
    Print (L"%c", (CHAR16)MacAddr[i]);
  }
  Print (L"\n");
}

/**
  Проверяет, соответствует ли MAC-адрес из UEFI переменной MAC-адресу сетевой карты.
  
  @param MacString     ASCII строка с MAC-адресом из UEFI переменной
  @param DeviceName    Буфер для имени устройства с совпадающим MAC (может быть NULL)
  @param DeviceNameSize Размер буфера для имени устройства
  
  @retval TRUE         MAC-адрес совпадает с MAC-адресом сетевой карты
  @retval FALSE        MAC-адрес не совпадает ни с одним MAC-адресом
**/
BOOLEAN
CheckMacAddressAgainstNetworkDevices (
  IN  CONST CHAR8    *MacString,
  OUT CHAR16         *DeviceName OPTIONAL,
  IN  UINTN          DeviceNameSize
  )
{
  EFI_STATUS                     Status;
  EFI_HANDLE                     *HandleBuffer;
  UINTN                          HandleCount;
  UINTN                          Index;
  EFI_SIMPLE_NETWORK_PROTOCOL    *Snp;
  EFI_DEVICE_PATH_PROTOCOL       *DevicePath;
  CHAR8                          CurrentMacStr[18];
  BOOLEAN                        Found = FALSE;
  
  // Для отладки
  Print(L"Target MAC: %a\n", MacString);
  
  // Получаем список всех устройств с Simple Network Protocol
  Status = gBS->LocateHandleBuffer(
                  ByProtocol,
                  &gEfiSimpleNetworkProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer
                  );
                  
  if (EFI_ERROR(Status) || HandleCount == 0) {
    Print(L"Warning: No network interfaces found on this system! Status: %r\n", Status);
    return FALSE;
  }
  
  Print(L"Found %d network interfaces\n", HandleCount);
  
  // Перебираем все сетевые устройства
  for (Index = 0; Index < HandleCount; Index++) {
    Status = gBS->HandleProtocol(
                    HandleBuffer[Index],
                    &gEfiSimpleNetworkProtocolGuid,
                    (VOID **)&Snp
                    );
                    
    if (EFI_ERROR(Status) || Snp == NULL) {
      Print(L"Warning: Failed to get SNP for interface %d. Status: %r\n", Index, Status);
      continue;
    }
    
    // Проверяем, инициализирован ли протокол
    if (Snp->Mode == NULL) {
      Print(L"Warning: SNP Mode is NULL for interface %d\n", Index);
      continue;
    }
    
    // Выводим информацию о состоянии сетевого интерфейса
    Print(L"Network Interface %d State: %d\n", Index, Snp->Mode->State);
    
    // Выводим информацию о MAC-адресе
    Print(L"Network Interface %d MAC: ", Index);
    
    // Преобразуем бинарный MAC-адрес в строку
    FormatMacAddress(
      &Snp->Mode->CurrentAddress.Addr[0],
      CurrentMacStr
    );
    
    // Выводим MAC-адрес
    Print(L"%a\n", CurrentMacStr);
    
    // Сравниваем MAC-адреса
    if (CompareMacAddresses(MacString, CurrentMacStr)) {
      Print(L"MAC MATCH FOUND for interface %d!\n", Index);
      Found = TRUE;
      
      // Если запрошено имя устройства, получаем его
      if (DeviceName != NULL && DeviceNameSize > 0) {
        ZeroMem(DeviceName, DeviceNameSize * sizeof(CHAR16));
        
        // Пытаемся получить Device Path для более дружественного имени
        Status = gBS->HandleProtocol(
                        HandleBuffer[Index],
                        &gEfiDevicePathProtocolGuid,
                        (VOID **)&DevicePath
                        );
                        
        if (!EFI_ERROR(Status) && DevicePath != NULL) {
          // Для простоты просто используем номер интерфейса
          UnicodeSPrint(DeviceName, DeviceNameSize * sizeof(CHAR16), 
                        L"Network Interface %u (MAC: ", Index);
                        
          // Добавляем MAC-адрес к имени
          for (UINTN i = 0; i < AsciiStrLen(CurrentMacStr); i++) {
            DeviceName[StrLen(DeviceName)] = (CHAR16)CurrentMacStr[i];
          }
          
          // Закрываем скобку и завершаем строку
          StrCatS(DeviceName, DeviceNameSize, L")");
        } else {
          // Если не удалось получить Device Path, используем индекс
          UnicodeSPrint(DeviceName, DeviceNameSize * sizeof(CHAR16), 
                        L"Network Interface %u (MAC: ", Index);
                        
          // Добавляем MAC-адрес к имени
          for (UINTN i = 0; i < AsciiStrLen(CurrentMacStr); i++) {
            DeviceName[StrLen(DeviceName)] = (CHAR16)CurrentMacStr[i];
          }
          
          // Закрываем скобку и завершаем строку
          StrCatS(DeviceName, DeviceNameSize, L")");
        }
      }
      
      break; // Нашли совпадение, выходим из цикла
    }
  }
  
  // Освобождаем буфер handles
  FreePool(HandleBuffer);
  
  return Found;
}

/**
  Проверяет, совпадает ли серийный номер из указанной EFI переменной с 
  серийными номерами в SMBIOS информации.
  
  @param SerialVarName    Имя переменной UEFI с серийным номером
  @param SerialVarGuid    GUID переменной UEFI (может быть NULL для поиска по всем GUID)
  
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
  EFI_GUID    FoundGuid;
  
  // Получаем серийный номер из переменной UEFI
  Status = GetVariableData (
            SerialVarName,
            SerialVarGuid,
            &SnVarData,
            &SnVarSize,
            &FoundGuid
            );
            
  if (EFI_ERROR (Status)) {
    Print (L"Error: Failed to get Serial Number from variable '%s': %r\n", SerialVarName, Status);
    return FALSE;
  }
  
  // Для информации, выводим GUID найденной переменной, если GUID не был указан явно
  if (SerialVarGuid == NULL) {
    Print (L"Found variable '%s' with GUID: %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X\n",
           SerialVarName,
           FoundGuid.Data1, FoundGuid.Data2, FoundGuid.Data3,
           FoundGuid.Data4[0], FoundGuid.Data4[1], FoundGuid.Data4[2],
           FoundGuid.Data4[3], FoundGuid.Data4[4], FoundGuid.Data4[5],
           FoundGuid.Data4[6], FoundGuid.Data4[7]);
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
  EFI_STATUS     Status;
  VOID           *SnVarData = NULL;         // Данные из переменной SerialVarName
  UINTN          SnVarSize = 0;
  BOOLEAN        SnMatches = FALSE;
  BOOLEAN        MacMatches = FALSE;
  UINTN          RetryCount;
  CHAR16         SnString[MAX_BUFFER_SIZE]; // Строка с серийным номером
  CHAR8          MacString[MAX_BUFFER_SIZE]; // Строка с MAC-адресом в ASCII
  CHAR16         MacDeviceName[MAX_BUFFER_SIZE]; // Имя устройства для MAC
  EFI_GUID       FoundGuid;
  BOOLEAN        SerialGuidAllocated = FALSE;
  BOOLEAN        MacGuidAllocated = FALSE;
  BOOLEAN        SnFlashed = FALSE;         // Флаг успешной прошивки SN
  EFI_INPUT_KEY  Key;                       // Для ожидания нажатия клавиши
  
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
              &SnVarSize,
              &FoundGuid
              );
              
    if (EFI_ERROR (Status)) {
      Print (L"Error: Failed to get Serial Number from variable '%s': %r\n", Config->SerialVarName, Status);
      return Status;
    }
    
    // Если GUID не был указан явно, сохраняем найденный GUID
    if (Config->SerialVarGuid == NULL) {
      Config->SerialVarGuid = AllocateZeroPool(sizeof(EFI_GUID));
      if (Config->SerialVarGuid == NULL) {
        Print(L"Error: Failed to allocate memory for GUID\n");
        FreePool(SnVarData);
        return EFI_OUT_OF_RESOURCES;
      }
      CopyMem(Config->SerialVarGuid, &FoundGuid, sizeof(EFI_GUID));
      SerialGuidAllocated = TRUE;
      
      Print(L"Found variable '%s' with GUID: %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X\n",
            Config->SerialVarName,
            Config->SerialVarGuid->Data1, Config->SerialVarGuid->Data2, Config->SerialVarGuid->Data3,
            Config->SerialVarGuid->Data4[0], Config->SerialVarGuid->Data4[1], Config->SerialVarGuid->Data4[2],
            Config->SerialVarGuid->Data4[3], Config->SerialVarGuid->Data4[4], Config->SerialVarGuid->Data4[5],
            Config->SerialVarGuid->Data4[6], Config->SerialVarGuid->Data4[7]);
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
    // Получаем MAC-адрес из переменной UEFI и преобразуем в ASCII строку
    Status = GetMacAddressAsAscii (
              Config->MacVarName,
              Config->MacVarGuid,
              MacString,
              sizeof(MacString),
              &FoundGuid
              );
              
    if (EFI_ERROR (Status)) {
      Print (L"Error: Failed to get MAC Address from variable '%s': %r\n", Config->MacVarName, Status);
      
      // Если SN не прошит и не совпадает, попробуем прошить его независимо от MAC
      if (Config->CheckSn && !SnMatches && !Config->CheckOnly) {
        goto FlashSerial;
      }
      
      if (SnVarData != NULL) {
        FreePool (SnVarData);
      }
      // Освобождаем память GUID, если была выделена
      if (SerialGuidAllocated && Config->SerialVarGuid != NULL) {
        FreePool(Config->SerialVarGuid);
      }
      return Status;
    }
    
    // Если GUID не был указан явно, сохраняем найденный GUID
    if (Config->MacVarGuid == NULL) {
      Config->MacVarGuid = AllocateZeroPool(sizeof(EFI_GUID));
      if (Config->MacVarGuid == NULL) {
        Print(L"Error: Failed to allocate memory for GUID\n");
        if (SnVarData != NULL) {
          FreePool(SnVarData);
        }
        // Освобождаем память GUID, если была выделена
        if (SerialGuidAllocated && Config->SerialVarGuid != NULL) {
          FreePool(Config->SerialVarGuid);
        }
        return EFI_OUT_OF_RESOURCES;
      }
      CopyMem(Config->MacVarGuid, &FoundGuid, sizeof(EFI_GUID));
      MacGuidAllocated = TRUE;
      
      Print(L"Found variable '%s' with GUID: %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X\n",
            Config->MacVarName,
            Config->MacVarGuid->Data1, Config->MacVarGuid->Data2, Config->MacVarGuid->Data3,
            Config->MacVarGuid->Data4[0], Config->MacVarGuid->Data4[1], Config->MacVarGuid->Data4[2],
            Config->MacVarGuid->Data4[3], Config->MacVarGuid->Data4[4], Config->MacVarGuid->Data4[5],
            Config->MacVarGuid->Data4[6], Config->MacVarGuid->Data4[7]);
    }
    
    // Выводим целевой MAC-адрес
    Print (L"Target MAC Address from EFI variable: ");
    PrintMacAddress(MacString);
    
    // Проверяем, совпадает ли MAC-адрес с каким-либо MAC-адресом сетевой карты
    ZeroMem(MacDeviceName, sizeof(MacDeviceName));
    MacMatches = CheckMacAddressAgainstNetworkDevices(
                   MacString,
                   MacDeviceName,
                   MAX_BUFFER_SIZE
                   );
                   
    if (MacMatches) {
      Print (L"MAC Address matches the network interface: %s\n", MacDeviceName);
    } else {
      Print (L"MAC Address does NOT match any network interface in the system.\n");
    }
    
  } else {
    // Если не проверяем MAC, считаем его совпадающим
    MacMatches = TRUE;
    Print (L"MAC Address check skipped.\n");
  }
  
  // Если работаем в режиме только проверки, выводим результат и завершаем работу
  if (Config->CheckOnly) {
    // Выводим итоговую информацию о проверке
    Print (L"\n=== Check Results ===\n");
    if (Config->CheckSn) {
      Print (L"Serial Number: %s\n", SnMatches ? L"MATCH" : L"MISMATCH");
    }
    if (Config->CheckMac) {
      Print (L"MAC Address: %s\n", MacMatches ? L"MATCH" : L"MISMATCH");
      if (MacMatches) {
        Print (L"Matching Network Interface: %s\n", MacDeviceName);
      }
    }
    
    if (SnVarData != NULL) {
      FreePool (SnVarData);
    }
    // Освобождаем память GUID, если была выделена
    if (SerialGuidAllocated && Config->SerialVarGuid != NULL) {
      FreePool(Config->SerialVarGuid);
    }
    if (MacGuidAllocated && Config->MacVarGuid != NULL) {
      FreePool(Config->MacVarGuid);
    }
    
    return (SnMatches && MacMatches) ? EFI_SUCCESS : EFI_DEVICE_ERROR;
  }
  
  // Если оба значения совпадают, ничего не делаем
  if (SnMatches && MacMatches) {
    Print (L"\n=== Verification Results ===\n");
    Print (L"Serial Number: MATCH\n");
    Print (L"MAC Address: MATCH\n");
    Print (L"\nSuccess: All values match the expected values.\n");
    
    // Если указан флаг --pw, выключаем систему
    if (Config->PowerDown) {
      Print (L"Power down flag is set. Shutting down system...\n");
      if (SnVarData != NULL) {
        FreePool (SnVarData);
      }
      // Освобождаем память GUID, если была выделена
      if (SerialGuidAllocated && Config->SerialVarGuid != NULL) {
        FreePool(Config->SerialVarGuid);
      }
      if (MacGuidAllocated && Config->MacVarGuid != NULL) {
        FreePool(Config->MacVarGuid);
      }
      return PowerDownSystem();
    }
    
    // Ждем нажатия клавиши перед завершением
    Print (L"\nPress any key to exit...\n");
    gBS->WaitForEvent (1, &gST->ConIn->WaitForKey, NULL);
    gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);
    
    if (SnVarData != NULL) {
      FreePool (SnVarData);
    }
    // Освобождаем память GUID, если была выделена
    if (SerialGuidAllocated && Config->SerialVarGuid != NULL) {
      FreePool(Config->SerialVarGuid);
    }
    if (MacGuidAllocated && Config->MacVarGuid != NULL) {
      FreePool(Config->MacVarGuid);
    }
    return EFI_SUCCESS;
  }
  
  // В противном случае, начинаем процесс обновления несовпадающих значений
  
FlashSerial:
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
        SnMatches = CheckSerialNumber(Config->SerialVarName, Config->SerialVarGuid);
        
        if (SnMatches) {
          Print (L"Serial Number was successfully flashed!\n");
          SnFlashed = TRUE;
          break;  // Прерываем цикл, так как серийник успешно прошит
        }
        
        Print (L"Failed to verify flashed Serial Number. Retrying...\n");
      } else {
        Print (L"Failed to run AMIDEEFIx64.efi. Error: %r\n", Status);
      }
    }
    
    // Если не удалось прошить серийный номер после 3 попыток
    if (!SnFlashed) {
      Print (L"\nCRITICAL ERROR: Failed to flash Serial Number after 3 attempts!\n");
      
      // Выводим итоговую информацию о проверке
      Print (L"\n=== Verification Results ===\n");
      Print (L"Serial Number: MISMATCH (Failed to flash)\n");
      if (Config->CheckMac) {
        Print (L"MAC Address: %s\n", MacMatches ? L"MATCH" : L"MISMATCH");
      }
      
      // Если включен флаг выключения, выключаем систему
      if (Config->PowerDown) {
        if (SnVarData != NULL) {
          FreePool (SnVarData);
        }
        // Освобождаем память GUID, если была выделена
        if (SerialGuidAllocated && Config->SerialVarGuid != NULL) {
          FreePool(Config->SerialVarGuid);
        }
        if (MacGuidAllocated && Config->MacVarGuid != NULL) {
          FreePool(Config->MacVarGuid);
        }
        return PowerDownSystem();
      }
      
      // Ждем нажатия клавиши перед завершением
      Print (L"\nPress any key to exit...\n");
      gBS->WaitForEvent (1, &gST->ConIn->WaitForKey, NULL);
      gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);
      
      if (SnVarData != NULL) {
        FreePool (SnVarData);
      }
      // Освобождаем память GUID, если была выделена
      if (SerialGuidAllocated && Config->SerialVarGuid != NULL) {
        FreePool(Config->SerialVarGuid);
      }
      if (MacGuidAllocated && Config->MacVarGuid != NULL) {
        FreePool(Config->MacVarGuid);
      }
      return EFI_DEVICE_ERROR;
    }
  }
  
  // Выводим итоговую информацию о проверке
  Print (L"\n=== Verification Results ===\n");
  if (Config->CheckSn) {
    Print (L"Serial Number: %s", SnMatches ? L"MATCH" : L"MISMATCH");
    if (SnFlashed) {
      Print (L" (Successfully flashed)\n");
    } else {
      Print (L"\n");
    }
  }
  if (Config->CheckMac) {
    Print (L"MAC Address: %s\n", MacMatches ? L"MATCH" : L"MISMATCH");
    if (MacMatches) {
      Print (L"Matching Network Interface: %s\n", MacDeviceName);
    }
  }
  
  // Если после прошивки SN все значения совпадают
  if (SnFlashed && SnMatches && MacMatches) {
    Print (L"\nSuccess: All values match the expected values after flashing.\n");
    
    // Если указан флаг --pw, выключаем систему
    if (Config->PowerDown) {
      Print (L"Power down flag is set.\n");
      if (SnVarData != NULL) {
        FreePool (SnVarData);
      }
      // Освобождаем память GUID, если была выделена
      if (SerialGuidAllocated && Config->SerialVarGuid != NULL) {
        FreePool(Config->SerialVarGuid);
      }
      if (MacGuidAllocated && Config->MacVarGuid != NULL) {
        FreePool(Config->MacVarGuid);
      }
      return PowerDownSystem();
    }
    
    // Ждем нажатия клавиши перед завершением
    Print (L"\nPress any key to exit...\n");
    gBS->WaitForEvent (1, &gST->ConIn->WaitForKey, NULL);
    gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);
    
    if (SnVarData != NULL) {
      FreePool (SnVarData);
    }
    // Освобождаем память GUID, если была выделена
    if (SerialGuidAllocated && Config->SerialVarGuid != NULL) {
      FreePool(Config->SerialVarGuid);
    }
    if (MacGuidAllocated && Config->MacVarGuid != NULL) {
      FreePool(Config->MacVarGuid);
    }
    return EFI_SUCCESS;
  }
  
  // После прошивки SN, если MAC не совпадает, перезагружаемся в систему (если включен флаг --pw)
  if (SnMatches && !MacMatches) {
    Print (L"\nSerial Number is correct, but MAC Address needs to be updated.\n");
    if (Config->PowerDown) {
      Print (L"Rebooting to system for MAC Address update...\n");
      if (SnVarData != NULL) {
        FreePool (SnVarData);
      }
      // Освобождаем память GUID, если была выделена
      if (SerialGuidAllocated && Config->SerialVarGuid != NULL) {
        FreePool(Config->SerialVarGuid);
      }
      if (MacGuidAllocated && Config->MacVarGuid != NULL) {
        FreePool(Config->MacVarGuid);
      }
      return RebootToBoot();
    } else {
      Print (L"Use --pw flag to reboot and update MAC.\n");
      
      // Ждем нажатия клавиши перед завершением
      Print (L"\nPress any key to exit...\n");
      gBS->WaitForEvent (1, &gST->ConIn->WaitForKey, NULL);
      gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);
    }
  }
  
  if (SnVarData != NULL) {
    FreePool (SnVarData);
  }
  // Освобождаем память GUID, если была выделена
  if (SerialGuidAllocated && Config->SerialVarGuid != NULL) {
    FreePool(Config->SerialVarGuid);
  }
  if (MacGuidAllocated && Config->MacVarGuid != NULL) {
    FreePool(Config->MacVarGuid);
  }
  return EFI_SUCCESS;
}

/**
  Выключает систему. Ожидает нажатия клавиши перед выключением.
  
  @retval EFI_SUCCESS   Команда выключения отправлена
  @retval другое        Ошибка при отправке команды выключения
**/
EFI_STATUS
PowerDownSystem (
  VOID
  )
{
  EFI_INPUT_KEY Key;
  
  Print (L"Press any key to shut down the system...\n");
  gBS->WaitForEvent (1, &gST->ConIn->WaitForKey, NULL);
  gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);
  
  Print (L"Shutting down system...\n");
  gRT->ResetSystem (EfiResetShutdown, EFI_SUCCESS, 0, NULL);
  
  // Этот код не должен выполниться, но возвращаем успешный статус на всякий случай
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
  Print (L"  --amid PATH      : Path to AMIDEEFIx64.efi (default: current directory)\n");
  Print (L"  --pw             : Power down/reboot system after operation (if needed)\n\n");
  
  Print (L"System Information:\n");
  Print (L"  --board-info     : Display detailed information about the motherboard\n\n");
  
  Print (L"Examples:\n");
  Print (L"  snsniff SerialNumber\n");
  Print (L"  snsniff SerialNumber --guid 12345678\n");
  Print (L"  snsniff --check --vsn SerialToFlash --vmac MacToCheck\n");
  Print (L"  snsniff --check-only --vsn SerialToFlash\n");
  Print (L"  snsniff --check --vsn SerialToFlash --vmac MacToCheck --pw\n");
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
  
  // Очищаем экран
  gST->ConOut->ClearScreen (gST->ConOut);
  
  // Инициализируем конфигурацию проверки
  ZeroMem (&Config, sizeof (CHECK_CONFIG));
  Config.SerialVarName = NULL;  // По умолчанию не задано
  Config.MacVarName = NULL;     // По умолчанию не задано
  Config.AmideEfiPath = L"AMIDEEFIx64.efi";
  Config.SerialVarGuid = NULL;  // NULL для поиска по всем GUID
  Config.MacVarGuid = NULL;     // NULL для поиска по всем GUID
  Config.CheckSn = FALSE;
  Config.CheckMac = FALSE;
  Config.CheckOnly = FALSE;
  Config.PowerDown = FALSE;     // По умолчанию не выключаем/перезагружаем систему
  
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
      } else if (StrCmp (Argv[Index], L"--pw") == 0) {
        // Включаем флаг выключения/перезагрузки системы
        Config.PowerDown = TRUE;
      }
    }
  }
  
  // Если указан GUID, пытаемся его распарсить и устанавливаем его для обоих параметров
  if (GuidPrefix != NULL) {
    EFI_GUID *TempGuid = AllocateZeroPool(sizeof(EFI_GUID));
    if (TempGuid == NULL) {
      Print (L"Error: Failed to allocate memory for GUID\n");
      return EFI_OUT_OF_RESOURCES;
    }
    
    if (ParseGuidPrefix (GuidPrefix, TempGuid)) {
      Config.SerialVarGuid = TempGuid;
      Config.MacVarGuid = TempGuid;
    } else {
      Print (L"Error: Invalid GUID prefix '%s'\n", GuidPrefix);
      FreePool(TempGuid);
      return EFI_INVALID_PARAMETER;
    }
  }
  
  // Режим вывода информации о материнской плате
  if (BoardInfoMode) {
    Status = DisplayBaseBoardInfo();
    // Освобождаем выделенную память для GUID, если была выделена
    if (GuidPrefix != NULL && Config.SerialVarGuid != NULL) {
      FreePool(Config.SerialVarGuid);
    }
    return (INTN)Status;
  }
  
  // Режим проверки (с прошивкой или без)
  if (CheckMode || CheckOnlyMode) {
    // Режим проверки и перепрошивки или только проверки
    if (!Config.CheckSn && !Config.CheckMac) {
      Print (L"Error: You must specify at least one value to check (--vsn or --vmac)\n");
      PrintUsage();
      // Освобождаем выделенную память для GUID, если была выделена
      if (GuidPrefix != NULL && Config.SerialVarGuid != NULL) {
        FreePool(Config.SerialVarGuid);
      }
      return EFI_INVALID_PARAMETER;
    }
    
    // Устанавливаем флаг CheckOnly для передачи в CheckAndFlashValues
    Config.CheckOnly = CheckOnlyMode;
    
    // Проверяем и перепрошиваем значения (если не CheckOnlyMode)
    Status = CheckAndFlashValues (&Config);
    
    // Здесь не нужно освобождать Config.SerialVarGuid, так как это делается в CheckAndFlashValues
  } else {
    // Стандартный режим - просто отображаем переменную
    Status = FindAndPrintVariable (VariableName, GuidPrefix, OutputType);
    
    // Освобождаем выделенную память для GUID, если была выделена
    if (GuidPrefix != NULL && Config.SerialVarGuid != NULL) {
      FreePool(Config.SerialVarGuid);
    }
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