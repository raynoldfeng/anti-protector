/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that app can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_DriverTest,
    0xddae6991,0x44c9,0x4c91,0xb5,0xe7,0x58,0x61,0x9a,0x2d,0xf7,0x53);
// {ddae6991-44c9-4c91-b5e7-58619a2df753}
