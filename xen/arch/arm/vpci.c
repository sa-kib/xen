/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * xen/arch/arm/vpci.c
 */
#include <xen/ioreq.h>
#include <xen/sched.h>
#include <xen/vpci.h>

#include <asm/ioreq.h>
#include <asm/mmio.h>

static pci_sbdf_t vpci_sbdf_from_gpa(uint16_t segment, uint8_t busn_start,
                                     paddr_t base_addr, paddr_t gpa)
{
    pci_sbdf_t sbdf;

    sbdf.sbdf = VPCI_ECAM_BDF(gpa - base_addr);
    sbdf.seg = segment;
    sbdf.bus += busn_start;
    return sbdf;
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

static int vpci_mmio_read(struct vcpu *v, mmio_info_t *info,
                          register_t *r, bool is_virt, pci_sbdf_t sbdf)
{
    /* data is needed to prevent a pointer cast on 32bit */
    unsigned long data;

    /*
     * For the passed through devices we need to map their virtual SBDF
     * to the physical PCI device being passed through.
     */
    if ( is_virt )
    {
        bool translated;

        read_lock(&v->domain->pci_lock);
        translated = vpci_translate_virtual_device(v->domain, &sbdf);
        read_unlock(&v->domain->pci_lock);

        if ( !translated )
        {
            int rc = IO_HANDLED;

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

            *r = ~0ul;
            return rc;
        }
    }

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

    ASSERT(!bridge == !is_hardware_domain(v->domain));

    if ( bridge )
        sbdf = vpci_sbdf_from_gpa(bridge->segment,
                                  bridge->cfg->busn_start,
                                  bridge->cfg->phys_addr,
                                  info->gpa);
    else
        sbdf = vpci_sbdf_from_gpa(0, 0, GUEST_VPCI_ECAM_BASE, info->gpa);

    return vpci_mmio_read(v, info, r, !bridge, sbdf);
}

static int vpci_mmio_read_child(struct vcpu *v, mmio_info_t *info,
                          register_t *r, void *p)
{
    struct pci_host_bridge *bridge = p;
    pci_sbdf_t sbdf;

    ASSERT(!bridge == !is_hardware_domain(v->domain));

    sbdf = vpci_sbdf_from_gpa(bridge->segment,
                              bridge->child_cfg->busn_start,
                              bridge->child_cfg->phys_addr,
                              info->gpa);

    return vpci_mmio_read(v, info, r, !bridge, sbdf);
}

static int vpci_mmio_write(struct vcpu *v, mmio_info_t *info,
                           register_t r, bool is_virt, pci_sbdf_t sbdf)
{
    /*
     * For the passed through devices we need to map their virtual SBDF
     * to the physical PCI device being passed through.
     */
    if ( is_virt )
    {
        bool translated;

        read_lock(&v->domain->pci_lock);
        translated = vpci_translate_virtual_device(v->domain, &sbdf);
        read_unlock(&v->domain->pci_lock);

        if ( !translated )
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
    }

    return vpci_ecam_write(sbdf, ECAM_REG_OFFSET(info->gpa),
                           1U << info->dabt.size, r);
}

static int vpci_mmio_write_root(struct vcpu *v, mmio_info_t *info,
                                register_t r, void *p)
{
    struct pci_host_bridge *bridge = p;
    pci_sbdf_t sbdf;

    ASSERT(!bridge == !is_hardware_domain(v->domain));

    if ( bridge )
        sbdf = vpci_sbdf_from_gpa(bridge->segment,
                                  bridge->cfg->busn_start,
                                  bridge->cfg->phys_addr,
                                  info->gpa);
    else
        sbdf = vpci_sbdf_from_gpa(0, 0, GUEST_VPCI_ECAM_BASE, info->gpa);

    return vpci_mmio_write(v, info, r, !bridge, sbdf);
}

static int vpci_mmio_write_child(struct vcpu *v, mmio_info_t *info,
                                register_t r, void *p)
{
    struct pci_host_bridge *bridge = p;
    pci_sbdf_t sbdf;

    ASSERT(!bridge == !is_hardware_domain(v->domain));

    sbdf = vpci_sbdf_from_gpa(bridge->segment,
                              bridge->child_cfg->busn_start,
                              bridge->child_cfg->phys_addr,
                              info->gpa);

    return vpci_mmio_write(v, info, r, !bridge, sbdf);
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
    if ( !has_vpci(d) )
        return 0;

    /*
     * The hardware domain gets as many MMIOs as required by the
     * physical host bridge.
     * Guests get the virtual platform layout: one virtual host bridge for now.
     */
    if ( is_hardware_domain(d) )
    {
        int ret;

        ret = pci_host_iterate_bridges_and_count(d, vpci_setup_mmio_handler_cb);
        if ( ret < 0 )
            return ret;
    }
    else
        register_mmio_handler(d, &vpci_mmio_handler,
                              GUEST_VPCI_ECAM_BASE, GUEST_VPCI_ECAM_SIZE, NULL);

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

    if ( !has_vpci(d) )
        return 0;

    if ( is_hardware_domain(d) )
    {
        int ret = pci_host_iterate_bridges_and_count(d, vpci_get_num_handlers_cb);

        if ( ret < 0 )
        {
            ASSERT_UNREACHABLE();
            return 0;
        }

        return ret;
    }

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

    return count;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

