#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <dirent.h>
#include <libgen.h>
#include "iosdiag.h"
#include "base_info.h"
#include "json_format.h"

enum disk_type {
	DISK_VIRTIO_BLK,
	DISK_SCSI,
	DISK_NVME
};

static int get_disk_type(char *buf)
{
	if (buf[0] == 'v' && buf[1] == 'd' && (buf[2] >= 'a' && buf[2] <= 'z'))
		return DISK_VIRTIO_BLK;
	else if (buf[0] == 's' && buf[1] == 'd' && (buf[2] >= 'a' && buf[2] <= 'z'))
		return DISK_SCSI;
	else if (!strncmp(buf, "nvme", 4))
		return DISK_NVME;
	return -1;
}

static char *get_abnormal_nvme(struct nvme_info *nvme)
{
	if ((nvme->cmd_ctx & 0xFFF) == 0x310 || (nvme->cmd_ctx & 0xFFF) == 0x30C)
		return "OS(Waitting for IO complete)";

	if (nvme->cq_rq_idx != -1 && nvme->cq_rq_idx >= nvme->cq_head)
		return "OS(Waitting for Irq handle)";

	if (nvme->sq_rq_idx != -1) {
		if (nvme->sq_rq_idx < nvme->sq_last_db)
			return "Disk(Waitting for disk handle)";

		if (nvme->sq_rq_idx >= nvme->sq_last_db && nvme->sq_rq_idx < nvme->sq_tail)
			return "OS(Driver not issue to disk)";
	}
	return "Unkown";
}

static char *get_abnormal_scsi(struct scsi_info *scsi)
{
	if (!scsi->done_hander_defined)
		return "OS(Waitting for SCSI-driver dispatch cmd)";
	return "Disk(Waitting for disk handle)";
}

static char *get_abnormal_vq(struct vq_info *vq)
{
	//device exec it done
	if (vq->rq_used_idx != -1 && vq->rq_used_idx < vq->used_idx)
		return "OS(Waitting for Irq handle)";

	if (vq->rq_avail_idx != -1) {
		//io issue to device, but device not exec it
		if (vq->rq_avail_idx < vq->last_kick_avail_idx)
			if (vq->rq_avail_idx >= vq->used_idx)
				//device not exec it
				return "Disk(Waitting for disk handle)";
			else
				if (vq->rq_avail_idx < vq->last_used_idx)
					return "OS(Waitting for IO complete)";
				else
					return "OS(Waitting for Irq handle)";
		else
			//io don't issue to device
			return "OS(Waitting for Driver issue to disk)";
	}

	if (vq->event) {
		if (vq->avail_idx == vq->last_avail_idx && vq->last_avail_idx == vq->used_idx
			&& vq->used_idx == vq->last_used_idx)
			return "OS(Waitting for IO complete)";

		if (vq->avail_idx == vq->last_avail_idx && vq->last_avail_idx == vq->used_idx
			&& vq->used_idx > vq->last_used_idx)
			return "OS(Waitting for Irq handle)";

		if (vq->avail_idx == vq->last_avail_idx && vq->last_avail_idx > vq->used_idx
			&& vq->used_idx == vq->last_used_idx)
			return "Disk(Waitting for disk handle)";

		if (vq->avail_idx == vq->last_avail_idx && vq->last_avail_idx > vq->used_idx
			&& vq->used_idx > vq->last_used_idx)
			return "Disk(Waitting for disk handle)";

		if (vq->avail_idx > vq->last_avail_idx && vq->last_avail_idx > vq->used_idx
			&& vq->used_idx == vq->last_used_idx)
			return "Disk(Waitting for disk handle)";

		if (vq->avail_idx > vq->last_avail_idx && vq->last_avail_idx > vq->used_idx
			&& vq->used_idx > vq->last_used_idx)
			return "Disk(Waitting for disk handle)";
	}
	return "Unkown";
}

static char *get_abnormal(struct rq_hang_info *rq_hi)
{
	if (rq_hi->io_issue_driver_ns == 0)
		return "OS(Waitting for Block issue to driver)";
	if (!strcmp(rq_hi->state, "complete"))
		return "OS(Waitting for IO complete)";

	if (get_disk_type(get_bdi_diskname()) == DISK_NVME)
		return get_abnormal_nvme(&rq_hi->nvme);
	else if (get_disk_type(get_bdi_diskname()) == DISK_SCSI)
		return get_abnormal_scsi(&rq_hi->scsi);
	else if (get_disk_type(get_bdi_diskname()) == DISK_VIRTIO_BLK)
		return get_abnormal_vq(&rq_hi->vq);
	else
		return "Unkown";
}

static void summary_convert_to_json(char *dest, struct rq_hang_info *rq_hi)
{
	sprintf(dest, "{\"time\":\"%s\","
				 "\"abnormal\":\"%s hang %ld us\","
				 "\"diskname\":\"%s\","
				 "\"iotype\":\"%s\","
				 "\"sector\":%lu,"
				 "\"datalen\":%u,"
				 "\"iostate\":\"%s\","
				 "\"cpu\":%d,"
				 "\"comm\":\"%s\","
				 "\"pid\":%d,"
				 "\"file\":\"%s%s\"}",
				 get_base_info_check_time_date(),
				 get_abnormal(rq_hi),
				 (rq_hi->check_hang_ns - rq_hi->io_start_ns) / 1000,
				 rq_hi->diskname,
				 rq_hi->op,
				 rq_hi->sector,
				 rq_hi->data_len,
				 rq_hi->state,
				 rq_hi->cpu,
				 get_base_info_comm() ? : "",
				 get_base_info_pid() ? : -1,
				 get_base_info_file() ? get_bdi_mnt_dir(rq_hi->diskname) : "",
				 get_base_info_file() ? : "");
				 //rq_hi->errors,
				 //rq_hi->cmd_flags);
}

static void rqinfo_convert_to_json(char *dest, struct rq_hang_info *rq_hi)
{
	int real_bio_cnt = 0;

	sprintf(dest, "\"rq_info\":{"
				 "\"tag\":%d,"
				 "\"internal_tag\":%d,"
				 "\"io_start\":%llu,"
				 "\"io_issue_driver\":%llu},",
				 rq_hi->tag,
				 rq_hi->internal_tag,
				 rq_hi->io_start_ns / 1000,
				 rq_hi->io_issue_driver_ns / 1000);
	if (rq_hi->first_bio.bio_addr) {
		struct bio_info *bio = &rq_hi->first_bio;

		if (strlen(bio->filename))
			set_base_info_file(bio->filename);
		set_base_info_comm(bio->comm);
		set_base_info_pid(bio->pid);
	}
}


static void vqinfo_convert_to_json(char *dest, struct vq_info *vq)
{
	sprintf(dest, "\"vq_info\":{"
			 "\"qid\":%d,"
			 "\"vring_num\":%d,"
			 "\"event\":%d,"
			 "\"last_used_idx\":%d,"
			 "\"used_idx\":%d,"
			 "\"last_avail_idx\":%d,"
			 "\"avail_idx\":%d,"
			 "\"last_kick_avail_idx\":%d,"
			 "\"rq_avail_idx\":%d,"
			 "\"rq_used_idx\":%d}",
			 vq->qid,
			 vq->vring_num,
			 vq->event,
			 vq->last_used_idx,
			 vq->used_idx,
			 vq->last_avail_idx,
			 vq->avail_idx,
			 vq->last_kick_avail_idx,
			 vq->rq_avail_idx,
			 vq->rq_used_idx,
			 vq->used_ring_flags,
			 vq->avail_ring_flags);
}

static char *cmd_ctx_to_str(unsigned long cmd_ctx)
{
	static char cmd_ctx_buf[24];

	switch (cmd_ctx & 0xFFF) {
		case 0x310:
			return "CMD_CTX_COMPLETED";
		case 0x30C:
			return "CMD_CTX_CANCELLED";
		case 0x314:
			return "CMD_CTX_INVALID";
		default:
			sprintf(cmd_ctx_buf, "%#lx", cmd_ctx);
			return cmd_ctx_buf;
	}
}

static void nvmeinfo_convert_to_json(char *dest, struct nvme_info *nvme)
{
	sprintf(dest, "\"nvme_info\":{"
			 "\"qid\":%d,"
			 "\"q_depth\":%d,"
			 "\"cq_head\":%d,"
			 "\"cq_end\":%d,"
			 "\"cq_rq_idx\":%d,"
			 "\"sq_tail\":%d,"
			 "\"sq_rq_idx\":%d,"
			 "\"last_sq_tail_db\":%d,"
			 "\"cmd_ctx\":\"%s\"}",
			 nvme->qid,
			 nvme->q_depth,
			 nvme->cq_head,
			 nvme->cq_end,
			 nvme->cq_rq_idx,
			 nvme->sq_tail,
			 nvme->sq_rq_idx,
			 nvme->sq_last_db,
			 cmd_ctx_to_str(nvme->cmd_ctx));
}

static void scsiinfo_convert_to_json(char *dest, struct scsi_info *scsi)
{
	sprintf(dest, "\"scsi_info\":{"
			 "\"is_mq\":\"%s\","
			 "\"done_hander_defined\":\"%s\"}",
			 scsi->is_mq ? "ture" : "false",
			 scsi->done_hander_defined ? "ture" : "false");
}

static void detail_convert_to_json(char *dest, struct rq_hang_info *rq_hi)
{
	char *diskname = get_bdi_diskname();

	sprintf(dest, "{\"diskname\":\"%s\","
				"\"time\":\"%s\",", 
				rq_hi->diskname,
				get_base_info_check_time_date());
	rqinfo_convert_to_json(dest + strlen(dest), rq_hi);
	if (get_disk_type(get_bdi_diskname()) == DISK_VIRTIO_BLK)
		vqinfo_convert_to_json(dest + strlen(dest), &rq_hi->vq);
	else if (get_disk_type(get_bdi_diskname()) == DISK_NVME)
		nvmeinfo_convert_to_json(dest + strlen(dest), &rq_hi->nvme);
	else if (get_disk_type(get_bdi_diskname()) == DISK_SCSI)
		scsiinfo_convert_to_json(dest + strlen(dest), &rq_hi->scsi);
	sprintf(dest + strlen(dest), "%s", "}");
}

void convert_to_json(char *dest, void *src)
{
	struct rq_hang_info *rq_hi = (struct rq_hang_info *)src;

	detail_convert_to_json(dest, rq_hi);
	sprintf(dest + strlen(dest), "%s", "\n");
	summary_convert_to_json(dest + strlen(dest), rq_hi);
	sprintf(dest + strlen(dest), "%s", "\n");
}

