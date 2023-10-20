/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * xen/arch/arm/vpci.c
 */
#include <xen/iocap.h>
#include <xen/ioreq.h>
#include <xen/sched.h>
#include <xen/vpci.h>
#include <xen/keyhandler.h>

#include <asm/mmio.h>
#include <asm/ioreq.h>

static bool_t vpci_sbdf_from_gpa(struct domain *d,
                                 const struct pci_host_bridge *bridge,
                                 paddr_t gpa, bool_t use_root, pci_sbdf_t *sbdf)
{
    ASSERT(sbdf);

    if ( bridge )
    {
        const struct pci_config_window *cfg = use_root ? bridge->cfg :
                                                         bridge->child_cfg;
        sbdf->sbdf = VPCI_ECAM_BDF(gpa - cfg->phys_addr);
        sbdf->seg = bridge->segment;
        sbdf->bus += cfg->busn_start;
    }
    else
    {
        bool translated;

        /*
         * For the passed through devices we need to map their virtual SBDF
         * to the physical PCI device being passed through.
         */
        sbdf->sbdf = VPCI_ECAM_BDF(gpa - GUEST_VPCI_ECAM_BASE);
        read_lock(&d->pci_lock);
        translated = vpci_translate_virtual_device(d, sbdf);
        read_unlock(&d->pci_lock);

        if ( !translated )
        {
            return false;
        }
    }
    return true;
}

bool vpci_ioreq_server_get_addr(const struct domain *d,
                                paddr_t gpa, uint64_t *addr)
{
    pci_sbdf_t sbdf;

    if ( !has_vpci(d) )
        return false;

    if ( gpa < GUEST_VPCI_ECAM_BASE ||
         gpa >= GUEST_VPCI_ECAM_BASE + GUEST_VPCI_ECAM_SIZE )
        return false;

    sbdf.sbdf = VPCI_ECAM_BDF(gpa - GUEST_VPCI_ECAM_BASE);
    *addr = ((uint64_t)sbdf.sbdf << 32) | ECAM_REG_OFFSET(gpa);

    return true;
}

static int vpci_mmio_read(struct vcpu *v, mmio_info_t *info, register_t *r,
                          pci_sbdf_t sbdf)
{
    /* data is needed to prevent a pointer cast on 32bit */
    unsigned long data;

    if ( vpci_ecam_read(sbdf, ECAM_REG_OFFSET(info->gpa),
                        1U << info->dabt.size, &data) )
    {
        *r = data;
        return 1;
    }

    *r = ~0ul;

    return 0;
}

static int vpci_mmio_read_root(struct vcpu *v, mmio_info_t *info,
                          register_t *r, void *p)
{
    struct pci_host_bridge *bridge = p;
    pci_sbdf_t sbdf;

    if ( !vpci_sbdf_from_gpa(v->domain, bridge, info->gpa,
                             true, &sbdf) )
    {
        int rc = IO_HANDLED;
        const uint8_t access_size = (1 << info->dabt.size) * 8;
        const uint64_t access_mask = GENMASK_ULL(access_size - 1, 0);

#if defined(CONFIG_HAS_VPCI_GUEST_SUPPORT) && defined(CONFIG_IOREQ_SERVER)
        if ( domain_has_ioreq_server(v->domain) )
        {
             rc = try_fwd_ioserv(guest_cpu_user_regs(), v, info);
             if ( rc == IO_HANDLED )
             {
                 *r = v->io.req.data;
                 v->io.req.state = STATE_IOREQ_NONE;
                 return IO_HANDLED;
             }
             else if ( rc == IO_UNHANDLED )
                 rc = IO_HANDLED;
         }
 #endif
         *r = access_mask;
         return rc;
    }

    return vpci_mmio_read(v, info, r, sbdf);
}

static int vpci_mmio_read_child(struct vcpu *v, mmio_info_t *info,
                          register_t *r, void *p)
{
    struct pci_host_bridge *bridge = p;
    pci_sbdf_t sbdf;

    if ( !vpci_sbdf_from_gpa(v->domain, bridge, info->gpa,
                             false, &sbdf) )
    {
        int rc = IO_HANDLED;
        const uint8_t access_size = (1 << info->dabt.size) * 8;
        const uint64_t access_mask = GENMASK_ULL(access_size - 1, 0);

#if defined(CONFIG_HAS_VPCI_GUEST_SUPPORT) && defined(CONFIG_IOREQ_SERVER)
        if ( domain_has_ioreq_server(v->domain) )
        {
             rc = try_fwd_ioserv(guest_cpu_user_regs(), v, info);
             if ( rc == IO_HANDLED )
             {
                 *r = v->io.req.data;
                 v->io.req.state = STATE_IOREQ_NONE;
                 return IO_HANDLED;
             }
             else if ( rc == IO_UNHANDLED )
                 rc = IO_HANDLED;
         }
 #endif
         *r = access_mask;
         return rc;
    }

    return vpci_mmio_read(v, info, r, sbdf);
}

static int vpci_mmio_write(struct vcpu *v, mmio_info_t *info,
                           register_t r, pci_sbdf_t sbdf)
{
    return vpci_ecam_write(sbdf, ECAM_REG_OFFSET(info->gpa),
                           1U << info->dabt.size, r);
}

static int vpci_mmio_write_root(struct vcpu *v, mmio_info_t *info,
                                register_t r, void *p)
{
    struct pci_host_bridge *bridge = p;
    pci_sbdf_t sbdf;

    if ( !vpci_sbdf_from_gpa(v->domain, bridge, info->gpa,
                             true, &sbdf) )
    {
        int rc = IO_HANDLED;

#if defined(CONFIG_HAS_VPCI_GUEST_SUPPORT) && defined(CONFIG_IOREQ_SERVER)
        if ( domain_has_ioreq_server(v->domain) )
        {
             rc = try_fwd_ioserv(guest_cpu_user_regs(), v, info);
             if ( rc == IO_HANDLED )
             {
                 v->io.req.state = STATE_IOREQ_NONE;
                 return IO_HANDLED;
             }
             else if ( rc == IO_UNHANDLED )
                 rc = IO_HANDLED;
         }
 #endif
         return rc;
    }

    return vpci_mmio_write(v, info, r, sbdf);
}

static int vpci_mmio_write_child(struct vcpu *v, mmio_info_t *info,
                                register_t r, void *p)
{
    struct pci_host_bridge *bridge = p;
    pci_sbdf_t sbdf;

    if ( !vpci_sbdf_from_gpa(v->domain, bridge, info->gpa,
                             false, &sbdf) )
    {
        int rc = IO_HANDLED;

#if defined(CONFIG_HAS_VPCI_GUEST_SUPPORT) && defined(CONFIG_IOREQ_SERVER)
        if ( domain_has_ioreq_server(v->domain) )
        {
             rc = try_fwd_ioserv(guest_cpu_user_regs(), v, info);
             if ( rc == IO_HANDLED )
             {
                 v->io.req.state = STATE_IOREQ_NONE;
                 return IO_HANDLED;
             }
             else if ( rc == IO_UNHANDLED )
                 rc = IO_HANDLED;
         }
 #endif
         return rc;
    }

    return vpci_mmio_write(v, info, r, sbdf);
}

static const struct mmio_handler_ops vpci_mmio_handler = {
    .read  = vpci_mmio_read_root,
    .write = vpci_mmio_write_root,
};

static const struct mmio_handler_ops vpci_mmio_handler_child = {
    .read  = vpci_mmio_read_child,
    .write = vpci_mmio_write_child,
};

static int vpci_setup_mmio_handler_cb(struct domain *d,
                                      struct pci_host_bridge *bridge)
{
    struct pci_config_window *cfg = bridge->cfg;
    int count = 1;

    if ( !pci_is_hardware_domain(d, bridge->segment, cfg->busn_start) )
        return 0;

    register_mmio_handler(d, &vpci_mmio_handler,
                          cfg->phys_addr, cfg->size, bridge);

    if ( bridge->child_ops )
    {
        struct pci_config_window *cfg = bridge->child_cfg;

        register_mmio_handler(d, &vpci_mmio_handler_child,
                              cfg->phys_addr, cfg->size, bridge);
        count++;
    }

    return count;
}

int domain_vpci_init(struct domain *d)
{
    int count;

    if ( !has_vpci(d) )
        return 0;

    /*
     * The hardware domain gets as many MMIOs as required by the
     * physical host bridge.
     * Guests get the virtual platform layout: one virtual host bridge for now.
     *
     * We don't know if this domain has bridges assigned,
     * so let's iterate the bridges and count them:
     * if the count is 0 then this domain doesn't own any
     * bridge and it can either be a control domain or just a
     * regular guest.
     */
    /* LORC: Revisit this  */
    count = pci_host_iterate_bridges_and_count(d, vpci_setup_mmio_handler_cb);
    if ( count )
        return 0;

    /* LORC: Revisit this  */
    if ( !is_control_domain(d) )
    {
        register_mmio_handler(d, &vpci_mmio_handler,
                              GUEST_VPCI_ECAM_BASE, GUEST_VPCI_ECAM_SIZE, NULL);
        iomem_permit_access(d, paddr_to_pfn(GUEST_VPCI_MEM_ADDR),
                            paddr_to_pfn(PAGE_ALIGN(GUEST_VPCI_MEM_ADDR +
                                                    GUEST_VPCI_MEM_SIZE - 1)));
    }

    return 0;
}

static int vpci_get_num_handlers_cb(struct domain *d,
                                    struct pci_host_bridge *bridge)
{
    int count = 1;

    if ( bridge->child_cfg )
        count++;

    return count;
}

unsigned int domain_vpci_get_num_mmio_handlers(struct domain *d)
{
    unsigned int count;
    int ret;

    if ( !has_vpci(d) )
        return 0;

    /*
     * We don't know if this domain has bridges assigned,
     * so let's iterate the bridges and count them:
     * if the count is 0 then this domain doesn't own any
     * bridge and it can either be a control domain or just a
     * regular guest.
     */
    ret = pci_host_iterate_bridges_and_count(d, vpci_get_num_handlers_cb);
    if ( ret < 0 )
    {
        ASSERT_UNREACHABLE();
        return 0;
    }
    if ( ret )
        return ret;

    if ( is_control_domain(d) )
        count = 0;
    else
    {
        /*
         * For guests each host bridge requires one region to cover the
         * configuration space. At the moment, we only expose a single host bridge.
         */
        count = 1;

        /*
         * There's a single MSI-X MMIO handler that deals with both PBA
         * and MSI-X tables per each PCI device being passed through.
         * Maximum number of emulated virtual devices is VPCI_MAX_VIRT_DEV.
         */
        if ( IS_ENABLED(CONFIG_HAS_PCI_MSI) )
            count += VPCI_MAX_VIRT_DEV;
    }

    return count;
}

static void dump_msi(unsigned char key)
{
    printk("MSI information:\n");

    vpci_dump_msi();
}

static int __init msi_setup_keyhandler(void)
{
    register_keyhandler('M', dump_msi, "dump MSI state", 1);
    return 0;
}
__initcall(msi_setup_keyhandler);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

