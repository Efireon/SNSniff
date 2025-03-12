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
  CHAR16    *SerialNumber;          // Ожидаемый серийный номер
  CHAR16    *MacAddress;            // Ожидаемый MAC-адрес
  CHAR16    *SerialVarName;         // Имя переменной UEFI с серийным номером
  CHAR16    *MacVarName;            // Имя переменной UEFI с MAC-адресом
  CHAR16    *AmideEfiPath;          // Путь к AMIDEEFIx64.efi
  BOOLEAN   CheckSn;                // Флаг проверки SN
  BOOLEAN   CheckMac;               // Флаг проверки MAC
  EFI_GUID  *SerialVarGuid;         // GUID для переменной с серийным номером
  EFI_GUID  *MacVarGuid;            // GUID для переменной с MAC-адресом
} CHECK_CONFIG;

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
  Находит EFI файл в текущей директории или указанном пути.
  
  @param FileName       Имя файла для поиска
  @param FilePath       Путь к файлу (если указан)
  @param FileHandle     Указатель на дескриптор файла (выход)
  
  @retval EFI_SUCCESS   Файл найден
  @retval другое        Ошибка при поиске файла
**/
EFI_STATUS
FindEfiFile (
  IN  CONST CHAR16                *FileName,
  IN  CONST CHAR16                *FilePath,
  OUT EFI_FILE_HANDLE             *FileHandle
  )
{
  EFI_STATUS                      Status;
  EFI_HANDLE                      *HandleBuffer;
  UINTN                           HandleCount;
  UINTN                           Index;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
  EFI_FILE_HANDLE                 Root;
  CHAR16                          FullPath[MAX_BUFFER_SIZE];
  
  // Инициализируем выходной параметр
  *FileHandle = NULL;
  
  // Находим все дескрипторы файловой системы
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiSimpleFileSystemProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer
                  );
                  
  if (EFI_ERROR (Status)) {
    Print (L"Error: Failed to locate file system handles\n");
    return Status;
  }
  
  // Подготавливаем полный путь к файлу
  if (FilePath != NULL && StrLen (FilePath) > 0) {
    // Используем указанный путь
    StrCpyS (FullPath, MAX_BUFFER_SIZE, FilePath);
    
    // Проверяем, нужно ли добавить разделитель
    if (FilePath[StrLen (FilePath) - 1] != L'\\') {
      StrCatS (FullPath, MAX_BUFFER_SIZE, L"\\");
    }
    
    // Добавляем имя файла
    StrCatS (FullPath, MAX_BUFFER_SIZE, FileName);
  } else {
    // Используем только имя файла (текущая директория)
    StrCpyS (FullPath, MAX_BUFFER_SIZE, FileName);
  }
  
  // Перебираем все дескрипторы файловой системы
  for (Index = 0; Index < HandleCount; Index++) {
    Status = gBS->HandleProtocol (
                    HandleBuffer[Index],
                    &gEfiSimpleFileSystemProtocolGuid,
                    (VOID **)&FileSystem
                    );
                    
    if (EFI_ERROR (Status)) {
      continue;
    }
    
    // Открываем корневую директорию
    Status = FileSystem->OpenVolume (FileSystem, &Root);
    if (EFI_ERROR (Status)) {
      continue;
    }
    
    // Пытаемся открыть файл
    Status = Root->Open (
                    Root,
                    FileHandle,
                    FullPath,
                    EFI_FILE_MODE_READ,
                    0
                    );
                    
    Root->Close (Root);
    
    if (!EFI_ERROR (Status)) {
      // Файл найден
      FreePool (HandleBuffer);
      return EFI_SUCCESS;
    }
  }
  
  // Файл не найден
  Print (L"Error: File '%s' not found\n", FullPath);
  FreePool (HandleBuffer);
  return EFI_NOT_FOUND;
}

/**
  Запускает внешнюю EFI программу.
  
  @param FilePath       Путь к EFI файлу
  @param Args           Массив аргументов
  @param ArgCount       Количество аргументов
  
  @retval EFI_SUCCESS   Программа успешно выполнена
  @retval другое        Ошибка при запуске программы
**/
EFI_STATUS
RunEfiProgram (
  IN CONST CHAR16    *FilePath,
  IN CHAR16          **Args,
  IN UINTN           ArgCount
  )
{
  EFI_STATUS                    Status;
  EFI_HANDLE                    ImageHandle;
  EFI_DEVICE_PATH_PROTOCOL      *DevicePath;
  EFI_LOADED_IMAGE_PROTOCOL     *LoadedImage;
  CHAR16                        *ArgsConcatenated;
  UINTN                         ArgsSize;
  UINTN                         Index;
  
  // Получаем путь к устройству
  Status = gBS->LocateProtocol (
                  &gEfiDevicePathProtocolGuid,
                  NULL,
                  (VOID **)&DevicePath
                  );
                  
  if (EFI_ERROR (Status)) {
    Print (L"Error: Failed to locate device path protocol\n");
    return Status;
  }
  
  // Загружаем изображение
  Status = gBS->LoadImage (
                  FALSE,
                  gImageHandle,
                  DevicePath,
                  (VOID *)FilePath,
                  StrSize (FilePath),
                  &ImageHandle
                  );
                  
  if (EFI_ERROR (Status)) {
    Print (L"Error: Failed to load image '%s'\n", FilePath);
    return Status;
  }
  
  // Получаем протокол загруженного изображения
  Status = gBS->HandleProtocol (
                  ImageHandle,
                  &gEfiLoadedImageProtocolGuid,
                  (VOID **)&LoadedImage
                  );
                  
  if (EFI_ERROR (Status)) {
    Print (L"Error: Failed to get loaded image protocol\n");
    gBS->UnloadImage (ImageHandle);
    return Status;
  }
  
  // Подготавливаем аргументы командной строки
  if (ArgCount > 0) {
    // Вычисляем размер буфера для аргументов
    ArgsSize = 0;
    for (Index = 0; Index < ArgCount; Index++) {
      ArgsSize += StrSize (Args[Index]) + sizeof (CHAR16); // Для разделителя
    }
    
    // Выделяем память для аргументов
    ArgsConcatenated = AllocateZeroPool (ArgsSize);
    if (ArgsConcatenated == NULL) {
      Print (L"Error: Failed to allocate memory for arguments\n");
      gBS->UnloadImage (ImageHandle);
      return EFI_OUT_OF_RESOURCES;
    }
    
    // Объединяем аргументы в одну строку
    for (Index = 0; Index < ArgCount; Index++) {
      StrCatS (ArgsConcatenated, ArgsSize / sizeof (CHAR16), Args[Index]);
      if (Index < ArgCount - 1) {
        StrCatS (ArgsConcatenated, ArgsSize / sizeof (CHAR16), L" ");
      }
    }
    
    // Устанавливаем аргументы командной строки
    LoadedImage->LoadOptions = ArgsConcatenated;
    LoadedImage->LoadOptionsSize = (UINT32)ArgsSize;
  }
  
  // Запускаем программу
  Status = gBS->StartImage (
                  ImageHandle,
                  NULL,
                  NULL
                  );
                  
  // Освобождаем память, если были аргументы
  if (ArgCount > 0) {
    FreePool (ArgsConcatenated);
  }
  
  if (EFI_ERROR (Status)) {
    Print (L"Error: Failed to start image '%s'\n", FilePath);
    gBS->UnloadImage (ImageHandle);
    return Status;
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
  VOID        *SnData = NULL;
  UINTN       SnSize = 0;
  VOID        *MacData = NULL;
  UINTN       MacSize = 0;
  BOOLEAN     SnMatches = FALSE;
  BOOLEAN     MacMatches = FALSE;
  UINTN       RetryCount;
  CHAR16      *AmideArgs[5];
  CHAR16      SsArg[MAX_BUFFER_SIZE];
  CHAR16      BsArg[MAX_BUFFER_SIZE];
  
  Print (L"Starting Serial Number and MAC verification...\n\n");
  
  // Проверяем, нужно ли проверять серийный номер
  if (Config->CheckSn) {
    // Получаем текущий серийный номер из UEFI
    Status = GetVariableData (
              Config->SerialVarName,
              Config->SerialVarGuid,
              &SnData,
              &SnSize
              );
              
    if (EFI_ERROR (Status)) {
      Print (L"Error: Failed to get Serial Number variable '%s'\n", Config->SerialVarName);
      return Status;
    }
    
    // Сравниваем серийный номер
    if (SnData != NULL && Config->SerialNumber != NULL) {
      Print (L"Current Serial Number: ");
      PrintUcsString (SnData, SnSize);
      Print (L"Expected Serial Number: %s\n", Config->SerialNumber);
      
      if (StrnCmp ((CHAR16*)SnData, Config->SerialNumber, StrLen (Config->SerialNumber)) == 0) {
        Print (L"Serial Number matches the expected value.\n");
        SnMatches = TRUE;
      } else {
        Print (L"Serial Number does NOT match the expected value!\n");
      }
      
      FreePool (SnData);
    }
  } else {
    // Если не проверяем SN, считаем его совпадающим
    SnMatches = TRUE;
  }
  
  // Проверяем, нужно ли проверять MAC-адрес
  if (Config->CheckMac) {
    // Получаем текущий MAC-адрес из UEFI
    Status = GetVariableData (
              Config->MacVarName,
              Config->MacVarGuid,
              &MacData,
              &MacSize
              );
              
    if (EFI_ERROR (Status)) {
      Print (L"Error: Failed to get MAC Address variable '%s'\n", Config->MacVarName);
      
      // Если SN не прошит, то пытаемся его прошить независимо от MAC
      if (!SnMatches) {
        goto FlashSerial;
      }
      
      return Status;
    }
    
    // Сравниваем MAC-адрес
    if (MacData != NULL && Config->MacAddress != NULL) {
      Print (L"Current MAC Address: ");
      PrintUcsString (MacData, MacSize);
      Print (L"Expected MAC Address: %s\n", Config->MacAddress);
      
      if (StrnCmp ((CHAR16*)MacData, Config->MacAddress, StrLen (Config->MacAddress)) == 0) {
        Print (L"MAC Address matches the expected value.\n");
        MacMatches = TRUE;
      } else {
        Print (L"MAC Address does NOT match the expected value!\n");
      }
      
      FreePool (MacData);
    }
  } else {
    // Если не проверяем MAC, считаем его совпадающим
    MacMatches = TRUE;
  }
  
FlashSerial:
  // Если оба значения совпадают, ничего не делаем
  if (SnMatches && MacMatches) {
    Print (L"\nSuccess: All values match the expected values.\n");
    return EFI_SUCCESS;
  }
  
  // Если серийный номер не совпадает, пытаемся его прошить
  if (!SnMatches) {
    Print (L"\nAttempting to flash Serial Number...\n");
    
    // Подготавливаем аргументы для AMIDEEFIx64.efi
    StrCpyS (SsArg, MAX_BUFFER_SIZE, L"/SS");
    StrCatS (SsArg, MAX_BUFFER_SIZE, L" ");
    StrCatS (SsArg, MAX_BUFFER_SIZE, Config->SerialNumber);
    
    StrCpyS (BsArg, MAX_BUFFER_SIZE, L"/BS");
    StrCatS (BsArg, MAX_BUFFER_SIZE, L" ");
    StrCatS (BsArg, MAX_BUFFER_SIZE, Config->SerialNumber);
    
    AmideArgs[0] = SsArg;
    AmideArgs[1] = BsArg;
    
    // Пытаемся перепрошить серийный номер до 3 раз
    for (RetryCount = 0; RetryCount < 3; RetryCount++) {
      Print (L"Flashing attempt %d...\n", RetryCount + 1);
      
      // Запускаем AMIDEEFIx64.efi
      Status = RunEfiProgram (
                Config->AmideEfiPath,
                AmideArgs,
                2
                );
                
      if (!EFI_ERROR (Status)) {
        // Проверяем, был ли серийный номер прошит успешно
        VOID *NewSnData = NULL;
        UINTN NewSnSize = 0;
        
        Status = GetVariableData (
                  Config->SerialVarName,
                  Config->SerialVarGuid,
                  &NewSnData,
                  &NewSnSize
                  );
                  
        if (!EFI_ERROR (Status) && NewSnData != NULL) {
          if (StrnCmp ((CHAR16*)NewSnData, Config->SerialNumber, StrLen (Config->SerialNumber)) == 0) {
            Print (L"Serial Number was successfully flashed!\n");
            FreePool (NewSnData);
            
            // Если MAC не совпадает, нужно перезагрузиться в систему
            if (!MacMatches) {
              Print (L"\nMAC Address needs to be updated. Rebooting to system for further updates...\n");
              return RebootToBoot();
            }
            
            return EFI_SUCCESS;
          }
          
          FreePool (NewSnData);
        }
        
        Print (L"Failed to verify flashed Serial Number. Retrying...\n");
      } else {
        Print (L"Failed to run AMIDEEFIx64.efi. Error: %r\n", Status);
      }
    }
    
    // Не удалось прошить серийный номер после 3 попыток
    Print (L"\nCRITICAL ERROR: Failed to flash Serial Number after 3 attempts!\n");
    return EFI_DEVICE_ERROR;
  }
  
  // Если только MAC-адрес не совпадает, но SN уже прошит
  if (SnMatches && !MacMatches) {
    Print (L"\nSerial Number is correct, but MAC Address needs to be updated.\n");
    Print (L"Rebooting to system for MAC Address update...\n");
    return RebootToBoot();
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
  Print (L"  --sn SERIAL      : Expected serial number\n");
  Print (L"  --mac MAC        : Expected MAC address\n");
  Print (L"  --vsn VARNAME    : Variable name that contains serial number (default: SerialNumber)\n");
  Print (L"  --vmac VARNAME   : Variable name that contains MAC address\n");
  Print (L"  --amid PATH      : Path to AMIDEEFIx64.efi (default: current directory)\n\n");
  
  Print (L"Examples:\n");
  Print (L"  snsniff SerialNumber\n");
  Print (L"  snsniff SerialNumber --guid 12345678\n");
  Print (L"  snsniff --check --sn ABC123 --mac 00:11:22:33:44:55 --vmac MacAddress\n");
  Print (L"  snsniff --check --sn ABC123 --amid \\EFI\\TOOLS\\AMIDEEFIx64.efi\n");
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
  CHECK_CONFIG Config;
  EFI_GUID     DefaultGuid = mCustomVarGuid;
  
  // Очищаем экран
  gST->ConOut->ClearScreen (gST->ConOut);
  
  // Инициализируем конфигурацию проверки
  ZeroMem (&Config, sizeof (CHECK_CONFIG));
  Config.SerialVarName = L"SerialNumber";
  Config.AmideEfiPath = L"AMIDEEFIx64.efi";
  Config.SerialVarGuid = &DefaultGuid;
  Config.MacVarGuid = &DefaultGuid;
  
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
      } else if (StrCmp (Argv[Index], L"--sn") == 0) {
        // Проверяем, что есть следующий аргумент
        if (Index + 1 < Argc) {
          Config.SerialNumber = Argv[Index + 1];
          Config.CheckSn = TRUE;
          Index++; // Пропускаем значение опции
        } else {
          Print (L"Error: Missing serial number value\n");
          PrintUsage();
          return EFI_INVALID_PARAMETER;
        }
      } else if (StrCmp (Argv[Index], L"--mac") == 0) {
        // Проверяем, что есть следующий аргумент
        if (Index + 1 < Argc) {
          Config.MacAddress = Argv[Index + 1];
          Config.CheckMac = TRUE;
          Index++; // Пропускаем значение опции
        } else {
          Print (L"Error: Missing MAC address value\n");
          PrintUsage();
          return EFI_INVALID_PARAMETER;
        }
      } else if (StrCmp (Argv[Index], L"--vsn") == 0) {
        // Проверяем, что есть следующий аргумент
        if (Index + 1 < Argc) {
          Config.SerialVarName = Argv[Index + 1];
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
  
  if (CheckMode) {
    // Режим проверки и перепрошивки
    if (!Config.CheckSn && !Config.CheckMac) {
      Print (L"Error: You must specify at least one value to check (--sn or --mac)\n");
      PrintUsage();
      return EFI_INVALID_PARAMETER;
    }
    
    // Проверяем и перепрошиваем значения
    Status = CheckAndFlashValues (&Config);
  } else {
    // Стандартный режим - просто отображаем переменную
    Status = FindAndPrintVariable (VariableName, GuidPrefix, OutputType);
  }
  
  // Ждем нажатия клавиши, если не используется rawtype и не режим проверки
  if (OutputType == OUTPUT_ALL && !CheckMode) {
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