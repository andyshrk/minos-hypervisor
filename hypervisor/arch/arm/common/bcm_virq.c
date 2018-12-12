/*
 * Copyright (C) 2018 Min Le (lemin9538@gmail.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <minos/minos.h>
#include <asm/arch.h>
#include <minos/vmodule.h>
#include <minos/irq.h>
#include <asm/io.h>
#include <minos/vmodule.h>
#include <minos/cpumask.h>
#include <minos/irq.h>
#include <minos/sched.h>
#include <minos/virq.h>
#include <minos/vdev.h>
#include <asm/of.h>
#include <asm/bcm_irq.h>

struct bcm2836_virq {
	struct vdev vdev;
	void *iomem;
	void *bcm2835_pending[NR_BANKS];
	void *bcm2835_enable[NR_BANKS];
	void *bcm2835_disable[NR_BANKS];
};

#define vdev_to_bcm_virq(vdev) \
	(struct bcm2836_virq *)container_of(vdev, struct bcm2836_virq, vdev)

extern int vgicv2_create_vm(void *item, void *arg);

static void bcm2836_virq_deinit(struct vdev *vdev)
{
	struct bcm2836_virq *bcm2836 = vdev_to_bcm_virq(vdev);

	free(bcm2836->iomem);
	vdev_release(vdev);
	free(bcm2836);
}

static void bcm2836_virq_reset(struct vdev *vdev)
{
	struct bcm2836_virq *bcm2836 = vdev_to_bcm_virq(vdev);

	memset(bcm2836->iomem, 0, PAGE_SIZE);
}

static int bcm2836_virq_read(struct vdev *vdev, gp_regs *regs,
		unsigned long address, unsigned long *read_value)
{
	/* guest can directly read the memory space */

	return 0;
}

static void inline bcm2835_virq_enable(struct vcpu *vcpu,
		int base, unsigned long *value)
{
	uint32_t bit;

	for_each_set_bit(bit, value, 32)
		virq_enable(vcpu, base + bit);
}

static void inline bcm2835_virq_disable(struct vcpu *vcpu,
		int base, unsigned long *value)
{
	uint32_t bit;

	for_each_set_bit(bit, value, 32)
		virq_disable(vcpu, base + bit);
}

static int bcm2835_virq_write(struct vdev *vdev, gp_regs *reg,
		unsigned long offset, unsigned long *value)
{
	struct vcpu *vcpu = current_vcpu;

	offset -= BCM2835_INC_OFFSET;

	switch (offset) {
	case BCM2835_IRQ_ENABLE1:
		bcm2835_virq_enable(vcpu, 32, value);
		break;
	case BCM2835_IRQ_ENABLE2:
		bcm2835_virq_enable(vcpu, 64, value);
		break;
	case BCM2835_IRQ_BASIC_ENABLE:
		bcm2835_virq_enable(vcpu, 96, value);	
		break;

	case BCM2835_IRQ_DISABLE1:
		bcm2835_virq_disable(vcpu, 32, value);
		break;
	case BCM2835_IRQ_DISABLE2:
		bcm2835_virq_disable(vcpu, 64, value);
		break;
	case BCM2835_IRQ_DISABLE_BASIC:
		bcm2835_virq_disable(vcpu, 96, value);
		break;
	default:
		pr_warn("unsupport action for bcm2836 virq\n");
		break;
	}

	return 0;
}

static int inline bcm2836_send_vsgi(struct vcpu *vcpu, struct vdev *vdev,
		unsigned long offset, unsigned long *value)
{
	void *base;
	uint32_t v;
	struct vcpu *target;
	struct vm *vm = vcpu->vm;
	int cpu = (offset - LOCAL_MAILBOX0_SET0) / 16;
	int sgi = __ffs((uint32_t)*value);
	struct bcm2836_virq *dev = vdev_to_bcm_virq(vdev); 

	pr_info("send vsgi %d %d\n", cpu, sgi);

	if ((cpu > vm->vcpu_nr) || (sgi >= 16))
		return -EINVAL;

	target = get_vcpu_in_vm(vm, cpu);
	if (!target)
		return -EINVAL;

	base = dev->iomem + (LOCAL_MAILBOX0_CLR0 + cpu * 16);

	/* set the read and clear register */
	v = readl_relaxed(base);
	writel_relaxed(v | (1 << sgi), base);

	return send_virq_to_vcpu(target, sgi);
}

static int inline bcm2836_clear_vsgi(struct vcpu *vcpu, struct vdev *vdev,
		unsigned long offset, unsigned long *value)
{
	uint32_t v;
	int sgi = __ffs((uint32_t)*value);
	int cpu = (offset - LOCAL_MAILBOX0_CLR0) / 16;
	struct vcpu *target;
	struct vm *vm = vcpu->vm;
	struct bcm2836_virq *dev = vdev_to_bcm_virq(vdev); 

	pr_info("clear vsgi %d %d\n", cpu, sgi);

	if ((cpu > vm->vcpu_nr) || (sgi >= 16))
		return -EINVAL;

	target = get_vcpu_in_vm(vm, cpu);
	if (!target)
		return -EINVAL;

	v = readl_relaxed(dev->iomem + offset);
	v &= ~((uint32_t)*value);

	clear_pending_virq(vcpu, sgi);
	return 0;
}

static int bcm2836_timer_int_action(struct vcpu *vcpu, struct vdev *vdev,
		unsigned long offset, unsigned long *value)
{
	int i;
	uint32_t v = (uint32_t)*value;
	struct vcpu *target;
	int cpu = (offset - LOCAL_TIMER_INT_CONTROL0) / 4;
	struct bcm2836_virq *dev = vdev_to_bcm_virq(vdev); 

	target = get_vcpu_in_vm(vcpu->vm, cpu);
	if (!target)
		return -EINVAL;

	/* update the value for vm read */
	writel_relaxed(v, dev->iomem + offset);

	/* timer treated as ppi in the system */
	for (i = 0; i < 4; i++) {
		if (v & (1 << i))
			virq_enable(vcpu, i + 16);
		else
			virq_disable(vcpu, i + 16);
	}

	return 0;
}

static int bcm2836_virq_write(struct vdev *vdev, gp_regs *reg,
		unsigned long address, unsigned long *write_value)
{
	unsigned long offset = address - BCM2836_INC_BASE;
	struct vcpu *vcpu = current_vcpu;

	if (offset >= BCM2835_INC_OFFSET)
		return bcm2835_virq_write(vdev, reg, offset, write_value);

	switch (offset) {
	case LOCAL_CONTROL:
	case LOCAL_PRESCALER:
		pr_info("set local timer freq pass\n");
		break;

	case LOCAL_MAILBOX_INT_CONTROL0...LOCAL_MAILBOX_INT_CONTROL3:
		/* mailbox interrupt aloways enabled */
		break;

	case LOCAL_TIMER_INT_CONTROL0...LOCAL_TIMER_INT_CONTROL3:
		bcm2836_timer_int_action(vcpu, vdev, offset, write_value);
		break;

	case LOCAL_MAILBOX_SET_START...LOCAL_MAILBOX_SET_END:
		/* send the ipi now only using mailbox0 */
		bcm2836_send_vsgi(vcpu, vdev, offset, write_value);
		break;
	
	case LOCAL_MAILBOX_CLR_START...LOCAL_MAILBOX_CLR_END:
		bcm2836_clear_vsgi(vcpu, vdev, offset, write_value);
		break;
	}

	return 0;
}

static int bcm_virq_create_vm(void *item, void *arg)
{
	struct vm *vm = item;
	void *base;
	struct bcm2836_virq *bcm2836;
	struct vdev *vdev;

	/* if the vm is not native using vgicv2 */
	if (!vm_is_native(vm))
		return vgicv2_create_vm(item, arg);

	base = zalloc(sizeof(struct bcm2836_virq));
	if (!base)
		return -ENOMEM;

	bcm2836 = (struct bcm2836_virq *)base;

	bcm2836->iomem = get_io_page();
	if (!bcm2836->iomem) {
		free(base);
		return -ENOMEM;
	}

	base = base + 0x200;
	bcm2836->bcm2835_pending[0] = base + 0x0;
	bcm2836->bcm2835_pending[1] = base + 0x04;
	bcm2836->bcm2835_pending[2] = base + 0x08;
	bcm2836->bcm2835_enable[0] = base + 0x18;
	bcm2836->bcm2835_enable[1] = base + 0x10;
	bcm2836->bcm2835_enable[2] = base + 0x14;
	bcm2836->bcm2835_disable[0] = base + 0x24;
	bcm2836->bcm2835_disable[1] = base + 0x1c;
	bcm2836->bcm2835_disable[2] = base + 0x20;

	memset(bcm2836->iomem, 0, PAGE_SIZE);
	vdev = &bcm2836->vdev;
	host_vdev_init(vm, vdev, BCM2836_INC_BASE, PAGE_SIZE);
	vdev_set_name(vdev, "bcm2836-irq");
	vdev->read = bcm2836_virq_read;
	vdev->write = bcm2836_virq_write;
	vdev->reset = bcm2836_virq_reset;
	vdev->deinit = bcm2836_virq_deinit;

	/* 
	 * map the io space to guest as read only Notice :
	 * bcm2836 base address is 7e00b200 which is not
	 * PAGE ALIG
	 *
	 * here map the bcm2835 and bcm2836 interrupt controller
	 * space all to 0x40000000
	 * 0x40000000 - 0x40000100 : bcm2836 local interrupt
	 * 0x40000200 - 0x40000300 : bcm2835 inc controller
	 *
	 */
	create_guest_mapping(vm, BCM2836_INC_BASE, (unsigned long)bcm2836->iomem,
			PAGE_SIZE, VM_IO | VM_RO);

	return 0;
}

int bcm_virq_init(unsigned long l1_base, size_t l1_size,
		unsigned long l2_base, size_t l2_size)
{
	return register_hook(bcm_virq_create_vm,
			MINOS_HOOK_TYPE_CREATE_VM_VDEV);
}
