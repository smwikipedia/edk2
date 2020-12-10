/** @file
  AsmReadIdtr function

  Copyright (c) 2006 - 2008, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/


#include "BaseLibInternals.h"


/**
  Reads the current Interrupt Descriptor Table Register(GDTR) descriptor.

  Reads and returns the current IDTR descriptor and returns it in Idtr. This
  function is only available on IA-32 and x64.

  @param  Idtr  The pointer to a IDTR descriptor.

**/
VOID
EFIAPI
InternalX86ReadIdtr (
  OUT     IA32_DESCRIPTOR           *Idtr
  )
{
  _asm {
    mov     eax, Idtr // Idtr is an argument on the stack that hold the IDTR structure.
    sidt    fword ptr [eax] // store the IDTR 6-byte structure to the address pointed to by EAX. (fword is 6 bytes: https://docs.microsoft.com/en-us/cpp/assembler/masm/fword)
  }
}
