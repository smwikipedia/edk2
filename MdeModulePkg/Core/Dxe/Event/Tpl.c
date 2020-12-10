/** @file
  Task priority (TPL) functions.

Copyright (c) 2006 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "DxeMain.h"
#include "Event.h"

/**
  Set Interrupt State.

  @param  Enable  The state of enable or disable interrupt

**/
VOID
CoreSetInterruptState (
  IN BOOLEAN      Enable
  )
{
  EFI_STATUS  Status;
  BOOLEAN     InSmm;

  if (gCpu == NULL) {
    return;
  }
  if (!Enable) {
    gCpu->DisableInterrupt (gCpu);
    return;
  }
  if (gSmmBase2 == NULL) {
    gCpu->EnableInterrupt (gCpu);
    return;
  }
  Status = gSmmBase2->InSmm (gSmmBase2, &InSmm);
  if (!EFI_ERROR (Status) && !InSmm) {
    gCpu->EnableInterrupt(gCpu);
  }
}


/**
  Raise the task priority level to the new level.
  High level is implemented by disabling processor interrupts.

  @param  NewTpl  New task priority level

  @return The previous task priority level

**/
EFI_TPL
EFIAPI
CoreRaiseTpl (
  IN EFI_TPL      NewTpl
  )
{
  EFI_TPL     OldTpl;

  OldTpl = gEfiCurrentTpl;
  if (OldTpl > NewTpl) {
    DEBUG ((EFI_D_ERROR, "FATAL ERROR - RaiseTpl with OldTpl(0x%x) > NewTpl(0x%x)\n", OldTpl, NewTpl));
    ASSERT (FALSE);
  }
  ASSERT (VALID_TPL (NewTpl));

  //
  // If raising to high level, disable interrupts
  //
  if (NewTpl >= TPL_HIGH_LEVEL  &&  OldTpl < TPL_HIGH_LEVEL) { //Comment: If the TPL is changing "across" the TPL_HIGH_LEVEL boundary, we need to re-disable the interrupt.
    CoreSetInterruptState (FALSE);
  }

  //
  // Set the new value
  //
  gEfiCurrentTpl = NewTpl;

  return OldTpl;
}




/**
  Lowers the task priority to the previous value.   If the new
  priority unmasks events at a higher priority, they are dispatched.

  @param  NewTpl  New, lower, task priority

**/
VOID
EFIAPI
CoreRestoreTpl (
  IN EFI_TPL NewTpl
  )
{
  EFI_TPL     OldTpl;
  EFI_TPL     PendingTpl;

  OldTpl = gEfiCurrentTpl;
  if (NewTpl > OldTpl) { //Comment: Check NewTpl must <= OldTpl
    DEBUG ((EFI_D_ERROR, "FATAL ERROR - RestoreTpl with NewTpl(0x%x) > OldTpl(0x%x)\n", NewTpl, OldTpl));
    ASSERT (FALSE);
  }
  ASSERT (VALID_TPL (NewTpl)); // Comment: Check a valid TPL must be <= TPL_HIGH_LEVEL

  //
  // If lowering below HIGH_LEVEL, make sure
  // interrupts are enabled
  //

  if (OldTpl >= TPL_HIGH_LEVEL  &&  NewTpl < TPL_HIGH_LEVEL) {//Comment: If dropping "accross" the TPL_HIGH_LEVEL boundary. The interrupt must have been disabled.
    gEfiCurrentTpl = TPL_HIGH_LEVEL; //Comment: This seems totally redundant? Because the newly assigned gEfiCurrentTpl is never checked before next assignment.
  }

  //
  // Dispatch any pending events
  //
  while (gEventPending != 0) {
    PendingTpl = (UINTN) HighBitSet64 (gEventPending);//Comment: gEventPending is checked but not modified here.
    if (PendingTpl <= NewTpl) { //Comment: No pending events with TPL > NewTpl, so nothing to dispatch.
      break;
    }

    gEfiCurrentTpl = PendingTpl; //Comment: we record the newly found PendingTpl which is higher than the NewTpl into the gEfiCurrentTpl because FW will execute at that TPL now. And this can help achieve the TPL "climbing".
    if (gEfiCurrentTpl < TPL_HIGH_LEVEL) {
      CoreSetInterruptState (TRUE);//Comment: Why enable interrupt here? Why not just rely on the line 151?
    }
    CoreDispatchEventNotifies (gEfiCurrentTpl); //Comment: gEventPending is modified here. CoreDispatchEventNnotifies() and CoreRestoreTpl() are coupled recursively.
  }

  //
  // Set the new value
  //

  gEfiCurrentTpl = NewTpl;

  //
  // If lowering below HIGH_LEVEL, make sure
  // interrupts are enabled
  //
  if (gEfiCurrentTpl < TPL_HIGH_LEVEL) {
    CoreSetInterruptState (TRUE);
  }

}
