#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <utime.h>

#ifdef _WIN32
	#define WIN32_LEAN_AND_MEAN
	#include <winsock2.h>
	#include <windows.h>
	#include <wincrypt.h>
	#include <fileapi.h>
	#include <sys/utime.h>

	#define socklen_t		int
	#define lstat			stat
	#define MSG_NOSIGNAL		0
	#define NO_INOTIFY

	#define WITH_SELECT

	#define INOTIFY_FLAGS		0
	#define INOTIFY_FILE_FLAGS	0

	static int lutimes(const char *sync_file, struct timeval times[2]) {
		struct _utimbuf time_buf;
		time_buf.actime = times[0].tv_sec;
		time_buf.modtime = times[1].tv_sec;
		return _utime(sync_file, &time_buf);
	}

	#undef MAX_PATH

	#define open(path, oflag , pmode)   _open(path, oflag | O_BINARY, 0);
#else
	#include <netdb.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#include <sys/inotify.h>
	#include <sys/socket.h>
	#include <sys/time.h>

	#define WITH_POLL

	#define INOTIFY_FLAGS		IN_CREATE | IN_DELETE | IN_CLOSE_WRITE | IN_ATTRIB | IN_MOVED_TO | IN_DONT_FOLLOW | IN_EXCL_UNLINK
	#define INOTIFY_FILE_FLAGS	IN_CLOSE_WRITE | IN_ATTRIB | IN_MOVED_TO | IN_DONT_FOLLOW | IN_EXCL_UNLINK
#endif

#include "khash.h"
#include "doops.h"
#include "monocypher.c"


#define EVENT_SIZE		(sizeof (struct inotify_event))
#define EVENT_BUF_LEN		(1024 * (EVENT_SIZE + 16 ))
#define INOTIFY_CACHE		EVENT_SIZE

#define MAX_MESSAGE		0x48000000
#define MAX_FILESIZE		MAX_MESSAGE - 0x400
#define MAX_PATH		4096

#define DEBUG_PRINT(f, ...)	fprintf(stderr, "%s [%i] ",timestamp(), __LINE__), fprintf(stderr, (f), ##__VA_ARGS__)				
#define DEBUG_INFO(...)		fprintf(stderr, __VA_ARGS__)

KHASH_MAP_INIT_INT(fd_to_name, char *)
KHASH_MAP_INIT_INT64(inotify_ignore, unsigned int)

static char * timestamp() {
	time_t now = time(NULL); 
	char * time = asctime(gmtime(&now));
	time[strlen(time)-1] = '\0'; // Remove \n
	return time;
}

struct remote_client {
	int sock;
	int sock_accept;
	char hostname[0x100];
	int port;
	unsigned char public_key[32];
	struct sockaddr_in servaddr;
	time_t timestamp;

	unsigned char *write_buffer;
	int write_buffer_len;

	unsigned char *write_buffer_a;
	int write_buffer_len_a;

	time_t connect_request;
};

static struct remote_client *hosts = NULL;
static int clients = 0;
static char *root_path = NULL;
static int root_path_len = 0;
static int enable_file_delete = 0;
static khash_t(inotify_ignore) *ignore_io = NULL;

void add_skip_event(const char *full_path) {
	struct stat buf;
	if (lstat(full_path, &buf))
		return;

	int absent;
	khint_t k = kh_put(inotify_ignore, ignore_io, buf.st_ino, &absent);
	kh_value(ignore_io, k) = buf.st_mtime;
}

int skip_event(const char *full_path) {
	struct stat buf;
	if (lstat(full_path, &buf))
		return 1;

	khint_t k = kh_get(inotify_ignore, ignore_io, buf.st_ino);
	if ((k != kh_end(ignore_io)) && (kh_exist(ignore_io, k))) {
		if (kh_value(ignore_io, k) == buf.st_mtime)
			return 1;
		return 0;
	}
	return 1;
}

int remove_skip_event(const char *full_path) {
	struct stat buf;
	if (lstat(full_path, &buf))
		return 0;

	khint_t k = kh_get(inotify_ignore, ignore_io, buf.st_ino);
	if ((k != kh_end(ignore_io)) && (kh_exist(ignore_io, k))) {
		kh_del(inotify_ignore, ignore_io, k); 
		return 1;
	}
	return 0;
}

int addToBuffer(struct doops_loop *loop, struct remote_client *host, int socket, unsigned char *buffer, int len) {
	if (!host)
		return -1;

	if (len <= 0)
		return len;

	if (host->sock == socket) {
		unsigned char *write_buffer = (unsigned char *)realloc(host->write_buffer, host->write_buffer_len + len);
		if (!write_buffer) {
			free(host->write_buffer);
			host->write_buffer = NULL;
			host->write_buffer_len = 0;
			return -1;
		}

		host->write_buffer = write_buffer;
		memcpy(host->write_buffer + host->write_buffer_len, buffer, len);
		host->write_buffer_len += len;
	} else {
		unsigned char *write_buffer = (unsigned char *)realloc(host->write_buffer_a, host->write_buffer_len_a + len);
		if (!write_buffer) {
			free(host->write_buffer_a);
			host->write_buffer_a = NULL;
			host->write_buffer_len_a = 0;
			return -1;
		}

		host->write_buffer_a = write_buffer;
		memcpy(host->write_buffer_a + host->write_buffer_len_a, buffer, len);
		host->write_buffer_len_a += len;
	}

	loop_resume_write_io(loop, socket);
	return len;
}

struct remote_client *findHost(int sock) {
	int i;
	if (sock <= 0)
		return NULL;

	for (i = 0; i < clients; i ++) {
		if ((hosts[i].sock == sock) || (hosts[i].sock_accept == sock)) {
			hosts[i].timestamp = time(NULL);
			if ((hosts[i].sock == sock) && (hosts[i].connect_request)) {
#ifndef _WIN32
				int arg = fcntl(sock, F_GETFL, NULL);
				if (arg > 0)
					fcntl(sock, F_SETFL, arg & (~O_NONBLOCK));

				hosts[i].connect_request = 0;
				DEBUG_INFO("connected to %s:%i\n", hosts[i].hostname, hosts[i].port);
#endif
			}
			return &hosts[i];
		}
	}

	return NULL;
}

void closeSocket(int sock) {
	if (sock <= 0)
		return;

	int i;
	for (i = 0; i < clients; i ++) {
		if (hosts[i].sock == sock) {
			hosts[i].sock = 0;
			free(hosts[i].write_buffer);
			hosts[i].write_buffer = 0;
			hosts[i].write_buffer_len = 0;
			break;
		}
		if (hosts[i].sock_accept == sock) {
			hosts[i].sock_accept = 0;
			free(hosts[i].write_buffer_a);
			hosts[i].write_buffer_a = 0;
			hosts[i].write_buffer_len_a = 0;
			break;
		}
	}
	close(sock);
	DEBUG_PRINT("remove socket\n");
}

int sharedSecret(unsigned char shared[32], unsigned char local_private_key[32], unsigned char remote_public_key[32]) {
	crypto_x25519(shared, local_private_key, remote_public_key);
	return 0;
}

int encrypt(const unsigned char *pt, unsigned char *ct, int size, unsigned char local_private_key[32], unsigned char remote_public_key[32], int ctr) {
	unsigned char key[32];
	sharedSecret(key, local_private_key, remote_public_key);
	u8 nonce[8];

	memset(nonce, 0, sizeof(nonce));
	nonce[7] = 4;

	if (!crypto_chacha20_djb(ct, pt, size, key, nonce, ctr))
		return 0;
	return size;
}

int encryptSign(const unsigned char *pt, unsigned char *ct, int size, unsigned char local_private_key[32], unsigned char remote_public_key[32], unsigned char private_key[64], int ctr) {
	int enc_size = encrypt(pt, ct, size, local_private_key, remote_public_key, ctr);
	crypto_eddsa_sign(ct + enc_size, private_key, ct, enc_size);
	return enc_size + 64;
}

int decrypt(const unsigned char *ct, unsigned char *pt, int size, unsigned char local_private_key[32], unsigned char remote_public_key[32], int ctr) {
	return encrypt(ct, pt, size, local_private_key, remote_public_key, ctr);
}

int decryptVerify(unsigned char *ct, unsigned char *pt, int size, unsigned char local_private_key[32], unsigned char remote_public_key[32], unsigned char public_key[32], int ctr) {
	if (size < 64)
		return -1;

	if (crypto_eddsa_check(ct + size - 64, public_key, ct, size - 64))
		return -1;

	return decrypt(ct, pt, size - 64, local_private_key, remote_public_key, ctr);
}

int sendData(struct doops_loop *loop, struct remote_client *host, int socket, const unsigned char *data, int len, unsigned char public_key[32], unsigned char private_key[64], unsigned char local_public_key[32], unsigned char local_private_key[32], unsigned char remote_public_key[32], khash_t(fd_to_name) *hash_table) {
	int msg_size = len + sizeof(int) + 64;
	unsigned char *buffer = (unsigned char *)malloc(msg_size);
	if (!buffer) {
		perror("malloc");
		loop_remove_io(loop, socket);
		closeSocket(socket);
		return -1;
	}

	*(int *)buffer = htonl(msg_size - sizeof(int));

	if (encryptSign(data, buffer + sizeof(int), len, local_private_key, remote_public_key, private_key, 0) <= 0) {
		DEBUG_PRINT("encryption error");
		free(buffer);
		loop_remove_io(loop, socket);
		closeSocket(socket);
		return -1;		
	}

	if (addToBuffer(loop, host, socket, buffer, msg_size) < 0) {
		loop_remove_io(loop, socket);
		closeSocket(socket);
		free(buffer);
		return -1;
	}

	free(buffer);
	return msg_size;
}

int notifyEvent(struct doops_loop *loop, char *path, const char *event_type, unsigned char public_key[32], unsigned char private_key[64], unsigned char local_public_key[32], unsigned char local_private_key[32], khash_t(fd_to_name) *hash_table) {
	struct stat buf;
	if (lstat(path, &buf)) {
		if (strcmp(event_type, "deleted")) {
			perror("lstat");
			return -1;
		}
		memset(&buf, 0, sizeof(buf));
	}
	unsigned char buffer[MAX_PATH * 2];
	int size = snprintf((char *)buffer, MAX_PATH * 2, "DESC\n%s:%u.%u:%o:%s\n", event_type, (unsigned int)buf.st_mtime, (unsigned int)buf.st_size, buf.st_mode, (char *)path + root_path_len + 1);
	int i = 0;
	for (i = 0; i < clients; i ++) {
		if ((hosts[i].sock > 0) && (!hosts[i].connect_request))
			sendData(loop, &hosts[i], hosts[i].sock, buffer, size, public_key, private_key, local_public_key, local_private_key, hosts[i].public_key, hash_table);
		else
		if (hosts[i].sock_accept > 0)
			sendData(loop, &hosts[i], hosts[i].sock_accept, buffer, size, public_key, private_key, local_public_key, local_private_key, hosts[i].public_key, hash_table);
	}
	return 0;
}

#ifdef NO_INOTIFY
int watch(int inotify_fd, const char *path_buf, khash_t(fd_to_name) *hash_table, int flags) {
	static int virtual_fd_watch = -1;
	int absent;
	khint_t k = kh_put(fd_to_name, hash_table, virtual_fd_watch, &absent);
	if (!absent)
		free((char *)kh_value(hash_table, k));
	kh_value(hash_table, k) = strdup(path_buf);

	virtual_fd_watch --;

	return -(virtual_fd_watch + 1);
}
#else
int watch(int inotify_fd, const char *path_buf, khash_t(fd_to_name) *hash_table, int flags) {
	int wd = inotify_add_watch(inotify_fd, path_buf, flags);
	if (wd >= 0) {
		int absent;
		khint_t k = kh_put(fd_to_name, hash_table, wd, &absent);
		if (!absent)
			free((char *)kh_value(hash_table, k));
		kh_value(hash_table, k) = strdup(path_buf);
		return wd;
	} else
		perror("inotify_add_watch");
	return wd;
}
#endif

int deleteFileOrDirectoryNoEvent(int inotify_fd, const char *path_buf, khash_t(fd_to_name) *hash_table) {
	int err = 0;
	if (rmdir(path_buf))
		err = unlink(path_buf);
	return err;
}

int mkFullDir(int inotify_fd, const char *filename_with_path, khash_t(fd_to_name) *hash_table) {
	char full_path[MAX_PATH];

	snprintf(full_path, MAX_PATH, "%s", filename_with_path);

	char *dir = full_path;
	char *name = dir;
	// ignore last part (filename)
	int last_err = 0;
	while ((dir) && (dir[0])) {
		char *dir_old = dir;
		dir = strchr(dir, '/');
		if (!dir)
			dir = strchr(dir_old, '\\');
		
		if (!dir)
			break;

		dir[0] = 0;

#ifdef _WIN32
		last_err = mkdir(full_path);
#else
		last_err = mkdir(full_path, S_IRWXU);
#endif
		if (!last_err) {
			struct utimbuf times;
			times.actime = 0;
			times.modtime = 0;
			utime(name, &times);

			watch(inotify_fd, full_path, hash_table, INOTIFY_FLAGS);
		}

		dir[0] = '/';
		dir ++;
	}
	
	return last_err;
}

int renameFileOrDirectoryNoEvent(int inotify_fd, const char *from, const char *to, khash_t(fd_to_name) *hash_table) {
	if (rmdir(to))
		unlink(to);
	int err = rename(from, to);
	if (err) {
		mkFullDir(inotify_fd, to, hash_table);
		err = rename(from, to);
	}
	if (err)
		DEBUG_PRINT("rename %s to %s error: %s\n", from, to, strerror(errno));
	return err;
}

int scan_directory(int inotify_fd, const char *path, khash_t(fd_to_name) *hash_table) {
	DIR *dir = opendir(path);
	if (!dir) {
		perror("opendir");
		return -1;
	}

	char path_buf[MAX_PATH];
	struct dirent *file;

	while ((file = readdir(dir))) {
		// skip ., .., and hidden files (begining with .)
		if ((!file->d_name) || (file->d_name[0] == '.'))
			continue;

		snprintf(path_buf, sizeof(path_buf), "%s/%s", path, file->d_name);
		struct stat buf;
		if (lstat(path_buf, &buf)) {
			perror("lstat");
			continue;
		}


#ifdef _WIN32
		if (((buf.st_mode & S_IFMT) == S_IFDIR) || ((buf.st_mode & S_IFMT) == S_IFREG)) {
#else
		if (((buf.st_mode & S_IFMT) == S_IFDIR) || ((buf.st_mode & S_IFMT) == S_IFREG) || ((buf.st_mode & S_IFMT) == S_IFLNK)) {
#endif
			if ((buf.st_mode & S_IFMT) == S_IFDIR) {
				watch(inotify_fd, path_buf, hash_table, INOTIFY_FLAGS);
				scan_directory(inotify_fd, path_buf, hash_table);
			} else
			if (buf.st_size <= MAX_FILESIZE)
				watch(inotify_fd, path_buf, hash_table, INOTIFY_FILE_FLAGS);
		}
	}
	closedir(dir);
	return 0;
}

void clearCache(char **to_delete, int *to_delete_files, const char *path_buf) {
	int i;
	int j;
	for (i = 0; i < *to_delete_files; i ++) {
		if (!strcmp(to_delete[i], path_buf)) {
			DEBUG_PRINT("clear cache [%s]\n", path_buf);
			free(to_delete[i]);
			for (j = i; j < *to_delete_files - 1; j ++)
				to_delete[j] = to_delete[j + 1];
			to_delete[*to_delete_files] = 0;
			(*to_delete_files) --;
			i --;
		}
	}
}

void notifyCache(struct doops_loop *loop, char **to_delete, int *to_delete_files, const char *method, unsigned char public_key[32], unsigned char private_key[64], unsigned char local_public_key[32], unsigned char local_private_key[32], khash_t(fd_to_name) *hash_table) {
	int i;
	for (i = 0; i < *to_delete_files; i ++) {
		DEBUG_PRINT("%s cache: %s\n", method, to_delete[i]);
		if (to_delete[i]) {
			notifyEvent(loop, to_delete[i], method, public_key, private_key, local_public_key, local_private_key, hash_table);
			free(to_delete[i]);
			to_delete[i] = 0;
		}
	}
	*to_delete_files = 0;
}

int addCache(char **to_delete, int *to_delete_files, int limit, const char *path_buf) {
	clearCache(to_delete, to_delete_files, path_buf);

	if (*to_delete_files < limit) {
		to_delete[(*to_delete_files) ++] = strdup(path_buf);
		return 1;
	}

	return 0;
}

#ifdef _WIN32
int consume(struct doops_loop *loop, char *path, HANDLE filechanged, OVERLAPPED *overlapped, char *change_buf, unsigned char public_key[32], unsigned char private_key[64], unsigned char local_public_key[32], unsigned char local_private_key[32], khash_t(fd_to_name) *hash_table) {
	if ((!overlapped) || (!change_buf))
		return -1;

	DWORD bytes_transferred;
	GetOverlappedResult(filechanged, overlapped, &bytes_transferred, FALSE);
	FILE_NOTIFY_INFORMATION *event = (FILE_NOTIFY_INFORMATION*)change_buf;
	char filename[MAX_PATH + 1];
	char full_path[MAX_PATH + 1];
	while (1) {
		DWORD name_len = event->FileNameLength / sizeof(wchar_t);

		int len = WideCharToMultiByte(CP_UTF8, 0, event->FileName, (int)name_len, filename, MAX_PATH, NULL, NULL);
		filename[len] = 0;
		int i;
		for (i = 0; i < len; i ++) {
			if (filename[i] == '\\')
				filename[i] = '/';
		}

		snprintf(full_path, sizeof(full_path), "%s/%s", path, filename);

		DEBUG_INFO("file %s changed\n", full_path);

		switch (event->Action) {
			case FILE_ACTION_ADDED:
				DEBUG_PRINT("created [%s]\n", full_path);
				notifyEvent(loop, full_path, "created", public_key, private_key, local_public_key, local_private_key, hash_table);
				break;
			case FILE_ACTION_REMOVED:
				DEBUG_PRINT("deleted [%s]\n", full_path);
				if (enable_file_delete)
					notifyEvent(loop, full_path, "deleted", public_key, private_key, local_public_key, local_private_key, hash_table);
				break;
			case FILE_ACTION_MODIFIED:
				DEBUG_PRINT("written [%s]\n", full_path);
				notifyEvent(loop, full_path, "write", public_key, private_key, local_public_key, local_private_key, hash_table);
				break;
			case FILE_ACTION_RENAMED_OLD_NAME:
				DEBUG_PRINT("move (old name) [%s] (ignored)\n", full_path);
				break;
			case FILE_ACTION_RENAMED_NEW_NAME:
				DEBUG_PRINT("move [%s]\n", full_path);
				notifyEvent(loop, full_path, "move", public_key, private_key, local_public_key, local_private_key, hash_table);
				break;
		}
		if (event->NextEntryOffset) {
			*((uint8_t**)&event) += event->NextEntryOffset;
		} else {
			break;
		}
	}
	return 0;
}
#else
int consume(struct doops_loop *loop, int inotify_fd, const char *events, int length, unsigned char public_key[32], unsigned char private_key[64], unsigned char local_public_key[32], unsigned char local_private_key[32], khash_t(fd_to_name) *hash_table) {
	if (!events)
		return -1;

	char path_buf[MAX_PATH];
	struct stat buf;

	int i = 0;
	khint_t k;

	char *to_delete[INOTIFY_CACHE];
	int to_delete_files = 0;

	char *to_sync[INOTIFY_CACHE];
	int to_sync_files = 0;

	while (i < length) {
		struct inotify_event *event = (struct inotify_event *)&events[i];
		k = kh_get(fd_to_name, hash_table, event->wd);
		if ((event->len) && (k != kh_end(hash_table) && (event->name[0] != '.'))) {
			snprintf(path_buf, sizeof(path_buf), "%s/%s", kh_value(hash_table, k), event->name);
			if (((!lstat(path_buf, &buf)) || (event->mask & IN_DELETE) || (event->mask & IN_MOVED_TO) || (event->mask & IN_MOVED_FROM))) {
				// filename/dirname event->name

				// check if delete operation is cached
				clearCache(to_delete, &to_delete_files, path_buf);

				if (event->mask & IN_CREATE) {
					if (event->mask & IN_ISDIR) {
						watch(inotify_fd, path_buf, hash_table, INOTIFY_FLAGS);
						DEBUG_PRINT("created [%s]\n", path_buf);
						scan_directory(inotify_fd, path_buf, hash_table);
						notifyEvent(loop, path_buf, "created", public_key, private_key, local_public_key, local_private_key, hash_table);
					} else {
						if (buf.st_size > MAX_FILESIZE) {
							DEBUG_PRINT("file too big [%s]\n", path_buf);
							i += EVENT_SIZE + event->len;
							continue;
						}
						add_skip_event(path_buf);
					}
				} else
				if (event->mask & IN_DELETE) {
					DEBUG_PRINT("deleted [%s]\n", path_buf);
					remove_skip_event(path_buf);
					if (enable_file_delete) {
						if (to_delete_files < INOTIFY_CACHE)
							to_delete[to_delete_files ++] = strdup(path_buf);
					}
				} else
				if (event->mask & IN_CLOSE_WRITE) {
					DEBUG_PRINT("written [%s]\n", path_buf);
					// remove_skip_event(path_buf);

					if (buf.st_size > MAX_FILESIZE) {
						DEBUG_PRINT("file too big [%s]\n", path_buf);
						i += EVENT_SIZE + event->len;
						continue;
					}
					clearCache(to_sync, &to_sync_files, path_buf);
					// if (!addCache(to_sync, &to_sync_files, INOTIFY_CACHE, path_buf))
					notifyEvent(loop, path_buf, "write", public_key, private_key, local_public_key, local_private_key, hash_table);
				} else
				if (event->mask & IN_ATTRIB) {
					DEBUG_PRINT("attr [%s] changed\n", path_buf);
					if (skip_event(path_buf)) {
						i += EVENT_SIZE + event->len;
						continue;
					}

					if (event->mask & IN_ISDIR) {
						watch(inotify_fd, path_buf, hash_table, INOTIFY_FLAGS);
						scan_directory(inotify_fd, path_buf, hash_table);
					} else {
						if (buf.st_size > MAX_FILESIZE) {
							DEBUG_PRINT("file too big [%s]\n", path_buf);
							i += EVENT_SIZE + event->len;
							continue;
						}
						add_skip_event(path_buf);
						// if (!addCache(to_sync, &to_sync_files, INOTIFY_CACHE, path_buf))
							notifyEvent(loop, path_buf, "attr", public_key, private_key, local_public_key, local_private_key, hash_table);
					}
				} else
				if (event->mask & IN_MOVED_TO) {
					// remove_skip_event(path_buf);
					DEBUG_PRINT("moved to [%s]\n", path_buf);
					if (event->mask & IN_ISDIR) {
						watch(inotify_fd, path_buf, hash_table, INOTIFY_FLAGS);
						scan_directory(inotify_fd, path_buf, hash_table);
					} else {
						add_skip_event(path_buf);
					}
					// if (!addCache(to_sync, &to_sync_files, INOTIFY_CACHE, path_buf))
						notifyEvent(loop, path_buf, "move", public_key, private_key, local_public_key, local_private_key, hash_table);
				}
			}
		}
		i += EVENT_SIZE + event->len;
	}
	notifyCache(loop, to_delete, &to_delete_files, "deleted", public_key, private_key, local_public_key, local_private_key, hash_table);
	// notifyCache(loop, to_sync, &to_sync_files, "move", public_key, private_key, local_public_key, local_private_key, hash_table);

	return 0;
}
#endif

char *list(khash_t(fd_to_name) *hash_table, int root_len, int *written_len) {
	int buf_size = 1024 * 1024;
	khint_t k;
	struct stat buf;

	char *buffer = (char *)malloc(buf_size);
	snprintf(buffer, buf_size, "LIST\n");

	*written_len = 5;

	for (k = 0; k < kh_end(hash_table); ++k) {
		if (kh_exist(hash_table, k)) {
			char *path = kh_value(hash_table, k);

			if (lstat(path, &buf))
				continue;

			*written_len += snprintf(buffer + *written_len, buf_size - *written_len, "%u.%u:%o:%s\n", (unsigned int)buf.st_mtime, (unsigned int)buf.st_size, (int)(buf.st_mode), path + root_len);
			if (buf_size - *written_len < 0x8000) {
				buf_size += 1024 * 1024;
				buffer = (char *)realloc(buffer, buf_size);
			}
		}
	}
	return buffer;
}

int writeFile(unsigned char *buf, int size, char *path) {
	unlink(path);
	int fd = open(path, O_WRONLY | O_CREAT, 0644);
	if (fd < 0) {
		perror("open");
		return -1;
	}

	int written = 0;
	do {
		int written_bytes = write(fd, buf + written, size - written);
		if (written_bytes < 0) {
			perror("write");
			close(fd);
			return -1;
		}
		written += written_bytes;
	} while (written < size);

	close(fd);
	return 0;
}

int readFile(unsigned char *buf, int size, char *path) {
	int fd = open(path, O_RDONLY, 0644);
	if (fd < 0) {
		perror("open");
		return -1;
	}
#ifndef _WIN32
	flock(fd, LOCK_SH);
#endif

	int bytes_read = 0;
	do {
		int bytes = read(fd, buf + bytes_read, size - bytes_read);
		if (bytes <= 0) {
			perror("read");
#ifndef _WIN32
			flock(fd, LOCK_UN);
#endif
			close(fd);
			return bytes_read;
		}
		bytes_read += bytes;
	} while (bytes_read < size);

#ifndef _WIN32
	flock(fd, LOCK_UN);
#endif
	close(fd);
	return bytes_read;
}

int mkdirAuto(char *full_path, mode_t mode, int inotify_fd, khash_t(fd_to_name) *hash_table) {
#ifdef _WIN32
	int err = mkdir(full_path);
#else
	int err = mkdir(full_path, mode);
#endif
	if (err) {
		mkFullDir(inotify_fd, full_path, hash_table);
#ifdef _WIN32
		err = mkdir(full_path);
#else
		err = mkdir(full_path, mode);
#endif
	}

	if (!err)
		watch(inotify_fd, full_path, hash_table, INOTIFY_FLAGS);
	return err;
}

int writeFileAuto(unsigned char *data, int size, int inotify_fd, khash_t(fd_to_name) *hash_table, int replace) {
	char full_path[MAX_PATH];
	static unsigned int file_write_index = 0;

	char *line = (char *)data;
	unsigned char *file_data = (unsigned char *)strchr((char *)data, '\n');
	if (!file_data)
		return -1;
	file_data[0] = 0;
	file_data ++;

	char *mode_str = strchr(line, ':');
	if (!mode_str)
		return -1;

	mode_str[0] = 0;
	mode_str ++;

	mode_t mode = 0;
	sscanf(mode_str, "%o", &mode);

	char *path = strchr(mode_str, ':');
	if ((!path) || (!path[0]))
		return -1;

	path[0] = 0;
	path ++;

	int mtime = atoi(line);

	int file_size = size - (file_data - (unsigned char *)line);
	
	snprintf(full_path, sizeof(full_path), "%s/%s", root_path, path);

	struct stat buf;
	if ((!replace) && (!lstat(full_path, &buf)) && (buf.st_mtime > mtime) && (buf.st_mode == mode)) {
		DEBUG_PRINT("local file is newer %s (%u > %u)\n",  full_path, (unsigned int)buf.st_mtime, (unsigned int)mtime);
		return 0;
	}

	char sync_file[MAX_PATH];

	char *filename = strrchr(path, '/');
	if (!filename)
		filename = strrchr(path, '\\');
	if (filename)
		filename ++;

	file_write_index ++;
	if (filename)
		snprintf(sync_file, sizeof(sync_file), ".sync.%08x.%s", file_write_index, filename);
	else
		snprintf(sync_file, sizeof(sync_file), ".sync.%08x", file_write_index);

#ifndef _WIN32
	if ((mode & S_IFMT) == S_IFLNK) {
		deleteFileOrDirectoryNoEvent(inotify_fd, sync_file, hash_table);
		if (symlink((char *)file_data, sync_file)) {
			perror("symlink");
			return -1;
		}

		struct timeval times[2];
		times[0].tv_sec = mtime;
		times[0].tv_usec = 0;
		times[1].tv_sec = mtime;
		times[1].tv_usec = 0;
		lutimes(sync_file, times);

		if (renameFileOrDirectoryNoEvent(inotify_fd, sync_file, full_path, hash_table)) {
			unlink(sync_file);
			return -1;
		}

		add_skip_event(full_path);
		return 0;
	} else
#endif
	{
		int fd = open(sync_file, O_WRONLY | O_CREAT | O_TRUNC, mode);
		if (fd < 0) {
			perror("open");
			return -1;
		}

#ifndef _WIN32
		flock(fd, LOCK_EX);
#endif

		int written = 0;
		while (written < file_size) {
			int written_bytes = write(fd, file_data + written, file_size - written);
			if (written_bytes < 0) {
				perror("write");
#ifndef _WIN32
				flock(fd, LOCK_UN);
#endif
				close(fd);
				unlink(sync_file);
				return -1;
			}
			written += written_bytes;
		}

#ifndef _WIN32
		flock(fd, LOCK_UN);
#endif
		close(fd);
	}

	struct timeval times[2];
	times[0].tv_sec = mtime;
	times[0].tv_usec = 0;
	times[1].tv_sec = mtime;
	times[1].tv_usec = 0;
	lutimes(sync_file, times);

	if (renameFileOrDirectoryNoEvent(inotify_fd, sync_file, full_path, hash_table)) {
		unlink(sync_file);
		return -1;
	}

	watch(inotify_fd, full_path, hash_table, INOTIFY_FILE_FLAGS);

	add_skip_event(full_path);

	return 0;
}

unsigned char *readFileAuto(char *path, int *size, const char *method) {
	unsigned char *buffer = NULL;

	*size = -1;

	struct stat buf;
	if (lstat(path, &buf)) {
		perror("lstat");
		return NULL;
	}
#ifndef _WIN32
	if ((buf.st_mode & S_IFMT) == S_IFLNK) {
		*size = MAX_PATH + 4096;
		buffer = (unsigned char *)malloc(*size);
		if (buffer) {
			int bytes_read = snprintf((char *)buffer, 4096, "%s\n%u.%u:%o:%s\n", method, (unsigned int)buf.st_mtime, (unsigned int)buf.st_size, buf.st_mode, (char *)path + root_path_len + 1);
			int link_buf = readlink(path, (char *)buffer + bytes_read, *size - bytes_read);
			if (link_buf < 0) {
				perror("readlink");
				*size = -1;
				free(buffer);
				return NULL;
			}
			*size = bytes_read + link_buf;
		} else
			perror("malloc");
		return buffer;
	}
#endif

	int fd = open(path, O_RDONLY, 0644);
	if (fd < 0) {
		perror("open");
		return NULL;
	}
#ifndef _WIN32
	flock(fd, LOCK_SH);
#endif

	*size = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);

	if ((*size >= 0) && (*size <= MAX_FILESIZE)) {
		buffer = (unsigned char *)malloc(*size + 4096);
		if (buffer) {
			int bytes_read = snprintf((char *)buffer, 4096, "DATA\n%u.%u:%o:%s\n", (unsigned int)buf.st_mtime, (unsigned int)buf.st_size, buf.st_mode, (char *)path + root_path_len + 1);
			*size += bytes_read;
			while (bytes_read < *size) {
				int bytes = read(fd, buffer + bytes_read, *size - bytes_read);
				if (bytes <= 0) {
					free(buffer);
#ifndef _WIN32
					flock(fd, LOCK_UN);
#endif
					close(fd);
					return NULL;
				}
				bytes_read += bytes;
			}
		} else
			perror("malloc");
	}
#ifndef _WIN32
	flock(fd, LOCK_UN);
#endif
	close(fd);
	return buffer;
}

int genKey(const char *path) {
	unsigned char temp[32];

#ifdef _WIN32
	HCRYPTPROV hProvider = 0;
	if (CryptAcquireContext(&hProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
		if (!CryptGenRandom(hProvider, sizeof(temp), (BYTE *)temp)) {
			CryptReleaseContext(hProvider, 0);
			return -1;
		}
		CryptReleaseContext(hProvider, 0);
	}
#else
	int fd = open("/dev/random", O_RDONLY);
	if (fd < 0) {
		perror("open");
		return -1;
	}
	size_t len = 0;
	while (len < sizeof(temp)) {
		ssize_t bytes = read(fd, temp + len, sizeof(temp) - len);
		if (bytes < 0) {
			close(fd);
			return -1;
		}
		len += bytes;
	}
	close(fd);
#endif

	unsigned char public_key[32];
	unsigned char private_key[64];

	crypto_eddsa_key_pair(private_key, public_key, temp);

	char full_path[MAX_PATH];

	snprintf(full_path, sizeof(full_path), "%s/.carbonpaper.key", path);
	if (writeFile(private_key, sizeof(private_key), full_path))
		return -1;

	fprintf(stderr, "generated key pair in [%s]\n", path);
	return 0;
}

int genLocalKey(unsigned char private_key[32], unsigned char public_key[32]) {
	unsigned char temp[32];

#ifdef _WIN32
	HCRYPTPROV hProvider = 0;
	if (CryptAcquireContext(&hProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
		if (!CryptGenRandom(hProvider, sizeof(temp), (BYTE *)temp)) {
			CryptReleaseContext(hProvider, 0);
			return -1;
		}
		CryptReleaseContext(hProvider, 0);
	}
#else
	int fd = open("/dev/random", O_RDONLY);
	if (fd < 0) {
		perror("open");
		return -1;
	}
	size_t len = 0;
	while (len < 32) {
		ssize_t bytes = read(fd, temp + len, 32 - len);
		if (bytes < 0) {
			close(fd);
			return -1;
		}
		len += bytes;
	}
	close(fd);
#endif

	crypto_blake2b(private_key, 32, temp, 32);
	crypto_x25519_public_key(public_key, private_key);

	fprintf(stderr, "generated local key pair\n");
	return 0;
}

int loadFile(const char *path, const char *filename, unsigned char *buf, int max_size) {
	char full_path[MAX_PATH];

	snprintf(full_path, sizeof(full_path), "%s/%s", path, filename);

	return readFile(buf, max_size, full_path);
}

int receiveData(struct doops_loop *loop, int socket, unsigned char public_key[32], unsigned char private_key[64], unsigned char local_public_key[32], unsigned char local_private_key[32], int inotify_fd, khash_t(fd_to_name) *hash_table) {
	unsigned char *buffer = NULL;
	unsigned int msg_size = 0;
	char full_path[MAX_PATH];

	ssize_t recv_size = recv(socket, (char *)&msg_size, sizeof(msg_size), MSG_NOSIGNAL);
	struct remote_client *host = findHost(socket);
	if ((recv_size <= 0) || (!host)) {
#ifndef _WIN32
		if ((host) && ((errno == EWOULDBLOCK) || (errno == EINPROGRESS))) {
			// not yet connected
			host->timestamp = time(NULL);
			return 0;
		}
#endif

		DEBUG_PRINT("cannot identify host\n");
		loop_remove_io(loop, socket);
		closeSocket(socket);
		return -1;
	}

	msg_size = ntohl(msg_size);
	if (msg_size == 32) {
		if (recv(socket, (char *)host->public_key, 32, MSG_NOSIGNAL) != 32) {
			perror("recv");
			loop_remove_io(loop, socket);
			closeSocket(socket);
			return -1;
		}
		DEBUG_PRINT("received host public key\n");
		return sendData(loop, host, socket, (const unsigned char *)"SYNC", 4, public_key, private_key, local_public_key, local_private_key, host->public_key, hash_table);
	}
	if (msg_size >= MAX_MESSAGE) {
		DEBUG_PRINT("message too big\n");
		loop_remove_io(loop, socket);
		closeSocket(socket);
		return -1;
	}

	buffer = (unsigned char *)malloc(msg_size);
	if (!buffer) {
		perror("malloc");
		loop_remove_io(loop, socket);
		closeSocket(socket);
		return -1;
	}
	unsigned int len_received = 0;
	while (len_received < msg_size) {
		recv_size = recv(socket, (char *)(buffer + len_received), msg_size - len_received, MSG_NOSIGNAL);
		if (recv_size <= 0) {
			perror("recv");
			loop_remove_io(loop, socket);
			closeSocket(socket);
			free(buffer);
			return -1;
		}
		len_received += recv_size;
	}

	unsigned char *pt = (unsigned char *)malloc(msg_size + 1);
	if (!pt) {
		perror("malloc");
		free(buffer);
		loop_remove_io(loop, socket);
		closeSocket(socket);
		return -1;
	}
	int size = decryptVerify(buffer, pt, len_received, local_private_key, host->public_key, public_key, 0);
	if (size <= 0) {
		free(pt);
		free(buffer);
		DEBUG_PRINT("signature verify failed\n");
		loop_remove_io(loop, socket);
		closeSocket(socket);
		return -1;
	} else {
		pt[size] = 0;
		if (size >= 4) {
			int is_desc = 0;
			if (memcmp(pt, "DESC", 4) == 0)
				is_desc = 1;	

			if (memcmp(pt, "PING", 4) == 0) {
				sendData(loop, host, socket, (const unsigned char *)"PONG", 4, public_key, private_key, local_public_key, local_private_key, host->public_key, hash_table);
			} else
			if (memcmp(pt, "SYNC", 4) == 0) {
				int data_size = 0;
				char *data = list(hash_table, root_path_len, &data_size);
				if (data)
					sendData(loop, host, socket, (const unsigned char *)data, data_size, public_key, private_key, local_public_key, local_private_key, host->public_key, hash_table);
				free(data);
			} else
			if (memcmp(pt, "PULL", 4) == 0) {
				snprintf(full_path, sizeof(full_path), "%s/%s", root_path, pt + 5);
				int fsize = -1;
				unsigned char *file_data = readFileAuto(full_path, &fsize, "DATA");
				if ((file_data) && (fsize > 0)) {
					DEBUG_PRINT("pull request %s\n", pt + 5);
					if (sendData(loop, host, socket, file_data, fsize, public_key, private_key, local_public_key, local_private_key, host->public_key, hash_table) <= 0)
						DEBUG_PRINT("send error\n");
				}
				free(file_data);
			} else
			if (memcmp(pt, "UPDT", 4) == 0) {
				snprintf(full_path, sizeof(full_path), "%s/%s", root_path, pt + 5);
				int fsize = -1;
				unsigned char *file_data = readFileAuto(full_path, &fsize, "FILE");
				if ((file_data) && (fsize > 0)) {
					DEBUG_PRINT("full file sync %s\n", pt + 5);
					if (sendData(loop, host, socket, file_data, fsize, public_key, private_key, local_public_key, local_private_key, host->public_key, hash_table) <= 0)
						DEBUG_PRINT("send error\n");
				}
				free(file_data);
			} else
			if (memcmp(pt, "DATA", 4) == 0) {
				writeFileAuto(pt + 5, size - 5, inotify_fd, hash_table, 0);
			} else
			if (memcmp(pt, "FILE", 4) == 0) {
				writeFileAuto(pt + 5, size - 5, inotify_fd, hash_table, 1);
			} else
			if ((memcmp(pt, "LIST", 4) == 0) || (is_desc)) {
				char *list = (char *)pt + 5;
				char *line = list;
				while (line) {
					list = strchr(list, '\n');
					if (list) {
						list[0] = 0;
						list ++;

						char *event_type = NULL;
						if (is_desc) {
							char *new_line = strchr(line, ':');
							if (new_line) {
								event_type = line;
								new_line[0] = 0;
								new_line ++;
								line = new_line;
							}
						}

						char *mode_str = strchr(line, ':');
						if (mode_str) {
							mode_str[0] = 0;
							mode_str ++;
							
							char *path = strchr(mode_str, ':');
							if ((path) && (path[0])) {
								path[0] = 0;
								path ++;

								if (!path[0]) {
									line = list;
									continue;
								}

								time_t mtime = atoi(line);
								mode_t mode = 0;
								sscanf(mode_str, "%o", &mode);

								char request_data[MAX_PATH + 5];
								snprintf(full_path, sizeof(full_path), "%s/%s", root_path, path);

								int sync = 0;
								struct stat buf;
								memset(&buf, 0, sizeof(buf));
								int lstat_error = lstat(full_path, &buf);

								int file_size = 0;
								char *ref = strchr(line, '.');
								if ((ref) && (ref[0])) {
									// check size
									file_size = atoi(ref + 1);
								}


								if (lstat_error) {
									if (((mode & S_IFMT) != S_IFDIR) || (mkdirAuto(full_path, mode & ~S_IFMT, inotify_fd, hash_table)))
										sync = 1;
								} else {
									if (buf.st_mtime < mtime) {
										sync = 1;
									} else
									if (buf.st_mtime > mtime) {
										sync = 2;
									} else
									if (buf.st_size < file_size) {
										sync = 1;
									}


									if ((sync == 1) && ((buf.st_mode & S_IFMT) == S_IFDIR) && ((mode & S_IFMT) == S_IFDIR)) {
										struct utimbuf times;
										times.actime = mtime;
										times.modtime = mtime;

										utime(full_path, &times);
										sync = 0;
									}
								}
								if (event_type) {
									if (strcmp(event_type, "deleted") == 0) {
										deleteFileOrDirectoryNoEvent(inotify_fd, full_path, hash_table);
										sync = 0;
									} else
									if (strcmp(event_type, "attr") == 0) {
										if (!lstat_error) {
											if (is_desc) {
												chmod(full_path, mode & ~S_IFMT);
												if (buf.st_mtime != mtime) {
													struct timeval times[2];
													times[0].tv_sec = mtime;
													times[0].tv_usec = 0;
													times[1].tv_sec = mtime;
													times[1].tv_usec = 0;

													DEBUG_PRINT("change mtime %s %i => %i\n", full_path, buf.st_mtime, mtime);
													if (!lutimes(full_path, times))
														add_skip_event(full_path);
												}
												if (mode != buf.st_mode) {
													DEBUG_PRINT("change mode %s %o => %o\n", full_path, buf.st_mode, mode);
													if (!chmod(full_path, mode & ~S_IFMT))
														add_skip_event(full_path);
												}
												sync = 0;
											} else
											if ((buf.st_mtime == mtime) && (sync)) {
												if ((mode != buf.st_mode) && (buf.st_size == file_size) && (!chmod(full_path, mode & ~S_IFMT))) {
													add_skip_event(full_path);
													sync = 0;
												}
											}
										}
									} else
									if (strcmp(event_type, "write") == 0) {
										sync = 4;
									}
								}

								switch (sync) {
									case 1:
									case 4:
										if (sync == 4) {
											DEBUG_PRINT("update %s\n", path);
											snprintf(request_data, sizeof(request_data), "UPDT\n%s", path);
										} else {
											DEBUG_PRINT("pull %s\n", path);
											snprintf(request_data, sizeof(request_data), "PULL\n%s", path);
										}
										if (sendData(loop, host, socket, (const unsigned char *)request_data, strlen(request_data), public_key, private_key, local_public_key, local_private_key, host->public_key, hash_table) <= 0) {
											DEBUG_PRINT("send error\n");
											list = NULL;
										}
										break;
								}
							}
						}
					}
					line = list;
				}
			}
		}
	}
	
	free(pt);
	free(buffer);

	host->timestamp = time(NULL);

	return 0;
}

void *validHost(struct doops_loop *loop, struct sockaddr_in *client_addr, int sock, unsigned char local_public_key[32]) {
	int i;
	for (i = 0; i < clients; i ++) {
		if (hosts[i].servaddr.sin_addr.s_addr == client_addr->sin_addr.s_addr) {
			if (hosts[i].sock_accept)
				close(hosts[i].sock_accept);
			hosts[i].sock_accept = sock;
		
			unsigned int size = htonl(32);

			addToBuffer(loop, &hosts[i], sock, (unsigned char *)&size, sizeof(int));
			addToBuffer(loop, &hosts[i], sock, local_public_key, 32);


			hosts[i].timestamp = time(NULL);

			return &hosts[i];
		}
	}

	return NULL;
}

int client_connect(struct doops_loop *loop, struct remote_client *host, unsigned char local_public_key[32]) {
	if (!host)
		return -1;

	if (host->sock) {
		loop_remove_io(loop, host->sock);
		close(host->sock);
		free(host->write_buffer);
		host->write_buffer = NULL;
		host->write_buffer_len = 0;
	}

	host->sock = socket(AF_INET, SOCK_STREAM, 0);

	host->servaddr.sin_family = AF_INET;
	host->servaddr.sin_addr.s_addr = inet_addr(host->hostname);
	host->servaddr.sin_port = htons(host->port);

	host->connect_request = 0;
#ifndef _WIN32
	int arg = fcntl(host->sock, F_GETFL, NULL);
	if (arg > 0)
		fcntl(host->sock, F_SETFL, arg | O_NONBLOCK);
#endif
	if (connect(host->sock, (struct sockaddr *)&host->servaddr, sizeof(host->servaddr))) {
#ifndef _WIN32
		if ((errno == EWOULDBLOCK) || (errno == EINPROGRESS))
			host->connect_request = time(NULL);

		if (!host->connect_request)
#endif
		{
			perror("connect");
			DEBUG_PRINT("error connecting to %s:%i\n", host->hostname, host->port);
			close(host->sock);
			host->sock = 0;
			return -1;
		}
	}

	unsigned int size = htonl(32);
	addToBuffer(loop, host, host->sock, (unsigned char *)&size, sizeof(int));
	addToBuffer(loop, host, host->sock, local_public_key, 32);

#ifndef _WIN32
	DEBUG_INFO("connect request to %s:%i\n", host->hostname, host->port);
#else
	DEBUG_INFO("connected to %s:%i\n", host->hostname, host->port);
#endif

	loop_add_io_data(loop, host->sock, DOOPS_READWRITE, host);

#ifndef _WIN32
	host->timestamp = time(NULL) - 470;
#else
	host->timestamp = time(NULL);
#endif
	return 0;
}

int main(int argc, char **argv) {
	static khash_t(fd_to_name) *hash_table;
	khint_t k;
	struct doops_loop loop;
	int fd;
	int wd;
	int port = 4804;
	const char *key_path = ".";
	static unsigned char private_key[64];
	static unsigned char public_key[32];
	static unsigned char local_private_key[32];
	static unsigned char local_public_key[32];

#ifdef _WIN32
	WORD wVersionRequested = MAKEWORD(2, 2);
	WSADATA wsaData;

	WSAStartup(wVersionRequested, &wsaData);
#endif

	fprintf(stderr, "carbonpaper v0.1 - real-time bidirectional directory synchronization tool\n(c)2023 by Eduard Suica (BSD-simplified license)\n\n");

	int path_index = 1;
	int i;
	for (i = 1; i < argc; i ++) {
		if (strcmp(argv[i], "--genkey") == 0) {
			if (i + 1 < argc) {
				i ++;
				key_path = argv[i];
				genKey(key_path);
				path_index = i + 1;
				if (path_index == argc)
					exit(0);
			} else {
				fprintf(stderr, "--genkey: key path missing\n");
				exit(1);
			}
		} else
		if (strcmp(argv[i], "--keypath") == 0) {
			if (i + 1 < argc) {
				i ++;
				key_path = argv[i];
				path_index = i + 1;
			} else {
				fprintf(stderr, "--keypath: key path missing\n");
				exit(1);
			}
		} else
		if (strcmp(argv[i], "--port") == 0) {
			if (i + 1 < argc) {
				i ++;
				port = atoi(argv[i]);
				path_index = i + 1;
			} else {
				fprintf(stderr, "--port: port number missing\n");
				exit(1);
			}
		} else
		if (strcmp(argv[i], "--host") == 0) {
			if (i + 1 < argc) {
				i ++;
				hosts = (struct remote_client *)realloc(hosts, sizeof(struct remote_client) * (clients + 1));
				if (!hosts) {
					perror("realloc");
					exit(1);
				}
				memset(&hosts[clients], 0, sizeof(struct remote_client));
				snprintf(hosts[clients].hostname, 0x100, "%s", argv[i]);
				char *port_ref = strchr(hosts[clients].hostname, ':');
				if (port_ref) {
					port_ref[0] = 0;
					port_ref ++;
					hosts[clients].port = atoi(port_ref);
				}
				if (!hosts[clients].port)
					hosts[clients].port = 4804;

				fprintf(stderr, "added host %s:%i\n", hosts[clients].hostname, hosts[clients].port);
				clients ++;
				path_index = i + 1;
			} else {
				fprintf(stderr, "--port: port number missing\n");
				exit(1);
			}
		} else
		if (strcmp(argv[i], "--enable-delete") == 0) {
			enable_file_delete = 1;
			path_index = i + 1;
		}
	}

	if (path_index != argc - 1) {
		fprintf(stderr, "Usage: %s [options] path_to_sync\n\nAvailable options:\n\t--genkey path\t\tgenerate new network key in path\n\t--keypath path\t\tuse network keys in given path (default is current path)\n\t--port    \t\tlisten on TCP port (default 4804)\n\t--host hostaddr[:port]\tconnect to client at hostaddr(ip)\n\t--enable-delete\t\tenable file delete propagation [disabled by default]\n\n", argv[0]);
		exit(1);
	}

	if (loadFile(key_path, ".carbonpaper.key", private_key, sizeof(private_key)) != sizeof(private_key)) {
		fprintf(stderr, "Error loading keys from [%s]\n\nTry using --genkey first.\n\n", key_path);
		exit(1);
	}

	memcpy(public_key, private_key + sizeof(public_key), sizeof(public_key));

	if (genLocalKey(local_private_key, local_public_key)) {
		fprintf(stderr, "Error generating local key pair.\n\n");
		exit(1);
	}

#ifndef NO_INOTIFY
	fd = inotify_init();

	if (fd < 0) {
		perror("inotify_init");
		exit(1);
	}

	wd = inotify_add_watch(fd, argv[path_index], INOTIFY_FLAGS);
	if (fd < 0) {
		perror("inotify_init");
		exit(1);
	}
#else
	fd = 0;
#endif

	static int server_socket;
	static int inotify_fd;

	inotify_fd = fd;
	server_socket = socket(AF_INET, SOCK_STREAM, 0);

	if (server_socket == -1) {
		perror("socket");
		exit(1);
	}

	struct sockaddr_in servaddr;
	memset(&servaddr, 0, sizeof(servaddr));

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(port);

	int val = 1;
	setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (const char *)&val, sizeof(int));

	if ((bind(server_socket, (struct sockaddr *)&servaddr, sizeof(servaddr))) != 0) {
		perror("bind");
		exit(0);
	}

	if (listen(server_socket, 1024)) {
		perror("listen");
		exit(0);
	}

	hash_table = kh_init(fd_to_name);
	ignore_io = kh_init(inotify_ignore);

	scan_directory(fd, argv[path_index], hash_table);

#ifndef _WIN32
	int absent;
	k = kh_put(fd_to_name, hash_table, wd, &absent);
	kh_value(hash_table, k) = strdup(argv[path_index]);

	signal(SIGPIPE, SIG_IGN);
#endif

	loop_init(&loop);

#ifndef NO_INOTIFY
	loop_add_io(&loop, fd, DOOPS_READ);
#endif
	loop_add_io(&loop, server_socket, DOOPS_READ);

	root_path = argv[path_index];
	root_path_len = strlen(argv[path_index]);

	if (hosts) {
		loop_schedule(&loop, {
			int i;
			for (i = 0; i < clients; i ++) {
				if ((!hosts[i].sock) || (time(NULL) - hosts[i].timestamp >= 480)) {
					client_connect(loop, &hosts[i], local_public_key);
				} else {
					if ((hosts[i].sock) && (!hosts[i].connect_request))
						sendData(loop, &hosts[i], hosts[i].sock, (const unsigned char *)"PING", 4, public_key, private_key, local_public_key, local_private_key, hosts[i].public_key, hash_table);
					if (hosts[i].sock_accept)
						sendData(loop, &hosts[i], hosts[i].sock_accept, (const unsigned char *)"PING", 4, public_key, private_key, local_public_key, local_private_key, hosts[i].public_key, hash_table);
				}
			}
		}, -4800);
	}

#ifdef _WIN32
	HANDLE filechanged = CreateFileA(argv[path_index], FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
	OVERLAPPED overlapped;
	overlapped.hEvent = CreateEvent(NULL, FALSE, 0, NULL);
	uint8_t change_buf[1024];

	if (ReadDirectoryChangesW(filechanged, change_buf, 1024, TRUE, FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE, NULL, &overlapped, NULL)) {
		loop_schedule(&loop, {
			if (WaitForSingleObject(overlapped.hEvent, 10) == WAIT_OBJECT_0) {
				consume(loop, argv[path_index], filechanged, &overlapped, change_buf, public_key, private_key, local_public_key, local_private_key, hash_table);
				ReadDirectoryChangesW(filechanged, change_buf, 1024, TRUE, FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE, NULL, &overlapped, NULL);
			}
		}, 480);
	} else {
		DEBUG_INFO("error initializing file watcher - local files will not be uploaded\n");
	}
#endif
	loop_on_write(&loop, {
		int sock = loop_event_socket(loop);
		struct remote_client *host = (struct remote_client *)loop_event_data(loop);
		if (!host) {
			loop_pause_write_io(loop, sock);
			return;
		}

		if (sock == host->sock) {
			if (!host->write_buffer_len) {
				loop_pause_write_io(loop, sock);
				return;
			}
			int sent = send(sock, (const char *)host->write_buffer, host->write_buffer_len, MSG_NOSIGNAL);
			if (sent < 0) {
				perror("send");
				free(host->write_buffer);
				host->write_buffer = NULL;
				host->write_buffer_len = 0;

				loop_remove_io(loop, sock);
				closeSocket(sock);
				return;
			}
			if (sent > 0) {
				host->timestamp = time(NULL);
				if (sent == host->write_buffer_len) {
					free(host->write_buffer);
					host->write_buffer = NULL;
					host->write_buffer_len = 0;
				} else {
					memmove(host->write_buffer, host->write_buffer + sent, host->write_buffer_len - sent);
					host->write_buffer_len -= sent;
					host->write_buffer = (unsigned char *)realloc(host->write_buffer, host->write_buffer_len);
				}
			}
		} else {
			if (!host->write_buffer_len_a) {
				loop_pause_write_io(loop, sock);
				return;
			}
			int sent = send(sock, (const char *)host->write_buffer_a, host->write_buffer_len_a, MSG_NOSIGNAL);
			if (sent < 0) {
				perror("send");
				free(host->write_buffer_a);
				host->write_buffer_a = NULL;
				host->write_buffer_len_a = 0;

				loop_remove_io(loop, sock);
				closeSocket(sock);
				return;
			}
			if (sent > 0) {
				host->timestamp = time(NULL);
				if (sent == host->write_buffer_len_a) {
					free(host->write_buffer_a);
					host->write_buffer_a = NULL;
					host->write_buffer_len_a = 0;
				} else {
					memmove(host->write_buffer_a, host->write_buffer_a + sent, host->write_buffer_len_a - sent);
					host->write_buffer_len_a -= sent;
					host->write_buffer_a = (unsigned char *)realloc(host->write_buffer_a, host->write_buffer_len_a);
				}
			}
		}
	});

	loop_on_read(&loop, {
#ifndef NO_INOTIFY
		char buffer[EVENT_BUF_LEN];
#endif
		int fd = loop_event_socket(loop);
		if (fd == server_socket) {
			struct sockaddr_in client_addr;
			socklen_t len = sizeof(client_addr);
			int sock = accept(server_socket, (struct sockaddr *)&client_addr, &len);
			if (sock < 0) {
				perror("accept");
			} else {
				void *host_data = validHost(loop, &client_addr, sock, local_public_key);
				if (host_data) {
					DEBUG_INFO("accepted connection request\n");
					struct timeval tv;
					tv.tv_sec = 1;
					tv.tv_usec = 0;
					setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
					setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
					loop_add_io_data(loop, sock, DOOPS_READWRITE, host_data);
				} else {
					DEBUG_PRINT("connection request from invalid address\n");
					close(sock);
				}
			}
		} else
#ifndef NO_INOTIFY
		if (fd == inotify_fd) {
			int length = read(fd, buffer, EVENT_BUF_LEN);
			consume(loop, fd, buffer, length, public_key, private_key, local_public_key, local_private_key, hash_table);
		} else
#endif
		{
			receiveData(loop, fd, public_key, private_key, local_public_key, local_private_key, inotify_fd, hash_table);
		}
	});
	loop_run(&loop);
	loop_deinit(&loop);

#ifndef NO_INOTIFY
	inotify_rm_watch(fd, wd);
#endif

	for (k = 0; k < kh_end(hash_table); ++k) {
		if (kh_exist(hash_table, k))
			free((char*)kh_value(hash_table, k));
	}

	free(hosts);

	kh_destroy(inotify_ignore, ignore_io);
	kh_destroy(fd_to_name, hash_table);

	hash_table = NULL;

#ifdef _WIN32
	CloseHandle(overlapped.hEvent);
	CloseHandle(filechanged);
	WSACleanup();
#else
	close(fd);
#endif
	return 0;
}
