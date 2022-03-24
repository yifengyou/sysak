
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <scsi/scsi.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_cmnd.h>
#include <linux/libata.h>
#include "iosdiag.h"

void get_scsi_info(struct scsi_info *scsi_i, struct request *rq)
{
	struct scsi_cmnd *cmd;

	if (rq->q->mq_ops) {
        scsi_i->is_mq = 1;
		cmd = blk_mq_rq_to_pdu(rq);
    } else
        cmd = rq->special;

    if (!cmd)
        return;
    scsi_i->done_hander_defined = cmd->scsi_done ? 1 : 0;
}
