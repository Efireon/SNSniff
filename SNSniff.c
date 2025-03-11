/**
  SNSniff - Приложение для чтения серийных номеров из UEFI переменных.
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
  Функция вывода справки по использованию.
**/
VOID
PrintUsage (
  VOID
  )
{
  Print (L"SNSniff - UEFI Serial Number Sniffer\n");
  Print (L"Usage: snsniff [variable_name] [options]\n\n");
  Print (L"Options:\n");
  Print (L"  --guid GUID      : Specify GUID prefix or full GUID\n");
  Print (L"  --rawtype TYPE   : Output only in specified format (hex, ascii, ucs)\n\n");
  Print (L"Examples:\n");
  Print (L"  snsniff SerialNumber\n");
  Print (L"  snsniff SerialNumber --guid 12345678\n");
  Print (L"  snsniff SerialNumber --rawtype hex\n");
  Print (L"  snsniff SerialNumber --guid 12345678 --rawtype ascii\n");
}

/**
  Точка входа в приложение.

  @param[in] ImageHandle    Хендл образа.
  @param[in] SystemTable    Указатель на системную таблицу.

  @retval EFI_SUCCESS       Приложение выполнилось успешно.
**/
INTN
EFIAPI
ShellAppMain (
  IN UINTN  Argc,
  IN CHAR16 **Argv
  )
{
  EFI_STATUS  Status;
  CONST CHAR16 *VariableName = L"SerialNumber";
  CONST CHAR16 *GuidPrefix = NULL;
  OUTPUT_TYPE OutputType = OUTPUT_ALL;
  UINTN       Index;
  
  // Очищаем экран
  gST->ConOut->ClearScreen (gST->ConOut);
  
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
      }
    }
  }
  
  // Ищем и выводим переменную
  Status = FindAndPrintVariable (VariableName, GuidPrefix, OutputType);
  
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
  // Инициализируем библиотеки Shell для обработки аргументов
  ShellInitialize();
  
  // Вызываем основную функцию приложения, которая обрабатывает аргументы
  return ShellAppMain (gEfiShellParametersProtocol->Argc,
                        gEfiShellParametersProtocol->Argv);
}