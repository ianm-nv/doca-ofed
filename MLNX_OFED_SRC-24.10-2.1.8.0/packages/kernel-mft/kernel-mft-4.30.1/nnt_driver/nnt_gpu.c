
#include "nnt_device_defs.h"
#include "nnt_gpu.h"

typedef struct pci_id_range_st
{
    unsigned int lower_bound;
    unsigned int upper_bound;
} pci_id_range;

pci_id_range GB100_PCI_IDS[] = {{0x2900, 0x29FF}, {0x2B00, 0x2BFF}, {0x2C00, 0x2CFF}, {0x2D00, 0x2DFF},
                                {0x2E00, 0x2EFF}, {0x2F00, 0x2F7F}, {0x3180, 0x31FF}, {0x3200, 0x327F},
                                {0x3300, 0x33FF}, {0x3400, 0x347F}};

pci_id_range GR100_PCI_IDS[] = {{0x3000, 0x30FF}, {0x3280, 0x32FF}};

int is_gb100_pci_device(u_int16_t pci_device_id)
{
    unsigned int i = 0;
    for (i = 0; i < sizeof(GB100_PCI_IDS) / sizeof(pci_id_range); i++)
    {
        if ((pci_device_id >= GB100_PCI_IDS[i].lower_bound) && (pci_device_id <= GB100_PCI_IDS[i].upper_bound))
        {
            return 1;
        }
    }
    return 0;
}

int is_gr100_pci_device(u_int16_t pci_device_id)
{
    unsigned int i = 0;
    for (i = 0; i < sizeof(GR100_PCI_IDS) / sizeof(pci_id_range); i++)
    {
        if ((pci_device_id >= GR100_PCI_IDS[i].lower_bound) && (pci_device_id <= GR100_PCI_IDS[i].upper_bound))
        {
            return 1;
        }
    }
    return 0;
}

int is_gpu_pci_device(u_int16_t pci_device_id)
{
    return (is_gb100_pci_device(pci_device_id) || is_gr100_pci_device(pci_device_id));
}