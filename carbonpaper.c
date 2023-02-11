#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <utime.h>

#include "khash.h"
#define WITH_POLL
#include "doops.h"
#include "monocypher.c"

#define INOTIFY_FLAGS	IN_CREATE | IN_DELETE | IN_CLOSE_WRITE | IN_ATTRIB  | IN_MOVED_TO | IN_DONT_FOLLOW

#define EVENT_SIZE	(sizeof (struct inotify_event))
#define EVENT_BUF_LEN	(1024 * (EVENT_SIZE + 16 ))

#define MAX_MESSAGE	0x8000000
#define MAX_PATH	4096

KHASH_MAP_INIT_INT(fd_to_name, char *)

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
};

static struct remote_client *hosts = NULL;
static int clients = 0;
static char *root_path = NULL;
static int root_path_len = 0;

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
			return &hosts[i];
		}
	}

	return NULL;
}

void closeSocket(int sock) {
	if (sock <= 0)
		return;

	for (int i = 0; i < clients; i ++) {
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
	fprintf(stderr, "remove socket\n");
}

int consume(int inotify_fd, const char *events, int length, khash_t(fd_to_name) *hash_table) {
	if (!events)
		return -1;

	char path_buf[MAX_PATH];
	struct stat buf;

	int i = 0;
	khint_t k;
	while (i < length) {
		struct inotify_event *event = (struct inotify_event *)&events[i];
		k = kh_get(fd_to_name, hash_table, event->wd);
		if ((event->len) && (k != kh_end(hash_table) && (event->name[0] != '.'))) {
			snprintf(path_buf, sizeof(path_buf), "%s/%s", kh_value(hash_table, k), event->name);

			if (((!lstat(path_buf, &buf)) || (event->mask & IN_DELETE)) && (((buf.st_mode & S_IFMT) == S_IFDIR) || ((buf.st_mode & S_IFMT) == S_IFREG) || ((buf.st_mode & S_IFMT) == S_IFLNK))) {
				// filename/dirname event->name
				if (event->mask & IN_CREATE) {
					fprintf(stdout, "created [%s]\n", path_buf);

					int wd = inotify_add_watch(inotify_fd, path_buf, INOTIFY_FLAGS);
					if (wd >= 0) {
						int absent;
						k = kh_put(fd_to_name, hash_table, wd, &absent);
						if (!absent)
							free((char *)kh_value(hash_table, k));
						kh_value(hash_table, k) = strdup(path_buf);
					} else
						perror("inotify_add_watch");
				

					if (event->mask & IN_ISDIR) {
						// directory created
					} else {
						// file created
					}
				} else
				if (event->mask & IN_DELETE) {
					if (inotify_rm_watch(inotify_fd, event->wd)) {
						perror("inotify_rm_watch");
					} else {
						if (kh_exist(hash_table, k)) {
							free((char *)kh_value(hash_table, k));
							kh_del(fd_to_name, hash_table, k);
						}
					}

					fprintf(stdout, "deleted [%s]\n", path_buf);
					if (event->mask & IN_ISDIR) {
						// directory deleted
					} else {
						// file deleted
					}
				} else
				if (event->mask & IN_CLOSE_WRITE) {
					if (inotify_rm_watch(inotify_fd, event->wd)) {
						perror("inotify_rm_watch");
					} else {
						if (kh_exist(hash_table, k)) {
							free((char *)kh_value(hash_table, k));
							kh_del(fd_to_name, hash_table, k);
						}
					}

					fprintf(stdout, "deleted [%s]\n", path_buf);
					if (event->mask & IN_ISDIR) {
						// directory deleted
					} else {
						// file deleted
					}
				} else
				if (event->mask & IN_ATTRIB) {
					fprintf(stdout, "attr [%s] changed\n", path_buf);
					if (event->mask & IN_ISDIR) {
						// directory attributes changed
					} else {
						// file attributes changed
					}
				} else
				if (event->mask & IN_MOVED_TO) {
					fprintf(stdout, "moved to [%s]\n", path_buf);
					if (event->mask & IN_ISDIR) {
						// directory attributes changed
					} else {
						// file attributes changed
					}
				}
			} else {
				perror("lstat");
			}
		}
		i += EVENT_SIZE + event->len;
	}
	return 0;
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


		if (((buf.st_mode & S_IFMT) == S_IFDIR) || ((buf.st_mode & S_IFMT) == S_IFREG) || ((buf.st_mode & S_IFMT) == S_IFLNK)) {
			int wd = inotify_add_watch(inotify_fd, path_buf, INOTIFY_FLAGS);
			if (wd >= 0) {
				int absent;
				khint_t k = kh_put(fd_to_name, hash_table, wd, &absent);
				if (!absent)
					free((char *)kh_value(hash_table, k));
				kh_value(hash_table, k) = strdup(path_buf);
			} else {
				perror("inotify_add_watch");
			}

			if ((buf.st_mode & S_IFMT) == S_IFDIR)
				scan_directory(inotify_fd, path_buf, hash_table);
		}
	}
	closedir(dir);
	return 0;
}

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

			*written_len += snprintf(buffer + *written_len, buf_size - *written_len, "%i:%o:%s\n", (int)buf.st_mtime, (int)(buf.st_mode), path + root_len);
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
	flock(fd, LOCK_SH);

	int bytes_read = 0;
	do {
		int bytes = read(fd, buf + bytes_read, size - bytes_read);
		if (bytes <= 0) {
			perror("read");
			flock(fd, LOCK_UN);
			close(fd);
			return bytes_read;
		}
		bytes_read += bytes;
	} while (bytes_read < size);

	flock(fd, LOCK_UN);
	close(fd);
	return bytes_read;
}

int writeFileAuto(unsigned char *data, int size) {
	char full_path[MAX_PATH];

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

	int mode = 0;
	sscanf(mode_str, "%o", &mode);

	char *path = strchr(mode_str, ':');
	if ((!path) || (!path[0]))
		return -1;

	path[0] = 0;
	path ++;

	int mtime = atoi(line);

	int file_size = size - (file_data - (unsigned char *)line);
	
	snprintf(full_path, sizeof(full_path), "%s/%s", root_path, path);

	const char *sync_file = ".sync";

	if ((mode & S_IFMT) == S_IFLNK) {
		unlink(sync_file);
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
		return 0;
	} else {
		int fd = open(sync_file, O_WRONLY | O_CREAT | O_TRUNC, mode);
		if (fd < 0) {
			perror("open");
			return -1;
		}

		flock(fd, LOCK_EX);

		int written = 0;
		while (written < file_size) {
			int written_bytes = write(fd, file_data + written, file_size - written);
			if (written_bytes < 0) {
				perror("write");
				flock(fd, LOCK_UN);
				close(fd);
				unlink(sync_file);
				return -1;
			}
			written += written_bytes;
		}

		flock(fd, LOCK_UN);
		close(fd);
	}

	struct utimbuf times;
	times.actime = mtime;
	times.modtime = mtime;
	utime(sync_file, &times);

	return 0;
}

unsigned char *readFileAuto(char *path, int *size) {
	unsigned char *buffer = NULL;

	*size = -1;

	struct stat buf;
	if (lstat(path, &buf)) {
		perror("lstat");
		return NULL;
	}

	if ((buf.st_mode & S_IFMT) == S_IFLNK) {
		*size = MAX_PATH + 4096;
		buffer = (unsigned char *)malloc(*size);
		if (buffer) {
			int bytes_read = snprintf((char *)buffer, 4096, "DATA\n%i:%o:%s\n", buf.st_mtime, buf.st_mode, (char *)path + root_path_len + 1);
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

	int fd = open(path, O_RDONLY, 0644);
	if (fd < 0) {
		perror("open");
		return NULL;
	}
	flock(fd, LOCK_SH);

	*size = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);

	if ((*size >= 0) && (*size <= MAX_MESSAGE - 0x400)) {
		buffer = (unsigned char *)malloc(*size + 4096);
		if (buffer) {
			int bytes_read = snprintf((char *)buffer, 4096, "DATA\n%i:%o:%s\n", buf.st_mtime, buf.st_mode, (char *)path + root_path_len + 1);
			*size += bytes_read;
			while (bytes_read < *size) {
				int bytes = read(fd, buffer + bytes_read, *size - bytes_read);
				if (bytes <= 0) {
					free(buffer);
					flock(fd, LOCK_UN);
					close(fd);
					return NULL;
				}
				bytes_read += bytes;
			}
		} else
			perror("malloc");
	}
	flock(fd, LOCK_UN);
	close(fd);
	return buffer;
}

int genKey(const char *path) {
	unsigned char temp[32];

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

	unsigned char public_key[32];
	unsigned char private_key[64];

	crypto_eddsa_key_pair(private_key, public_key, temp);

	char full_path[MAX_PATH];

	snprintf(full_path, sizeof(full_path), "%s/.private_key", path);
	if (writeFile(private_key, sizeof(private_key), full_path))
		return -1;

	snprintf(full_path, sizeof(full_path), "%s/.public_key", path);
	if (writeFile(public_key, sizeof(public_key), full_path))
		return -1;

	fprintf(stdout, "generated key pair in [%s]\n", path);
	return 0;
}

int genLocalKey(unsigned char private_key[32], unsigned char public_key[32]) {
	unsigned char temp[32];

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

	crypto_blake2b(private_key, 32, temp, 32);
	crypto_x25519_public_key(public_key, private_key);

	fprintf(stdout, "generated local key pair\n");
	return 0;
}

int sharedSecret(unsigned char shared[32], unsigned char local_private_key[32], unsigned char remote_public_key[32]) {
	crypto_x25519(shared, local_private_key, remote_public_key);
	return 0;
}

int loadFile(const char *path, const char *filename, unsigned char *buf, int max_size) {
	char full_path[MAX_PATH];

	snprintf(full_path, sizeof(full_path), "%s/%s", path, filename);

	return readFile(buf, max_size, full_path);
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
		fprintf(stderr, "encryption error");
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

int receiveData(struct doops_loop *loop, int socket, unsigned char public_key[32], unsigned char private_key[64], unsigned char local_public_key[32], unsigned char local_private_key[32], khash_t(fd_to_name) *hash_table) {
	unsigned char *buffer = NULL;
	unsigned int msg_size = 0;
	char full_path[MAX_PATH];

	ssize_t recv_size = recv(socket, &msg_size, sizeof(msg_size), MSG_NOSIGNAL);
	struct remote_client *host = findHost(socket);
	if ((recv_size <= 0) || (!host)) {
		fprintf(stderr, "cannot identify host\n");
		loop_remove_io(loop, socket);
		closeSocket(socket);
		return -1;
	}

	msg_size = ntohl(msg_size);
	if (msg_size == 32) {
		if (recv(socket, host->public_key, 32, MSG_NOSIGNAL) != 32) {
			perror("recv");
			loop_remove_io(loop, socket);
			closeSocket(socket);
			return -1;
		}
		fprintf(stderr, "received host public key\n");
		return sendData(loop, host, socket, (const unsigned char *)"SYNC", 4, public_key, private_key, local_public_key, local_private_key, host->public_key, hash_table);
	}
	if (msg_size >= MAX_MESSAGE) {
		fprintf(stderr, "message too big\n");
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
	int len_received = 0;
	while (len_received < msg_size) {
		recv_size = recv(socket, buffer + len_received, msg_size - len_received, MSG_NOSIGNAL);
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
		fprintf(stderr, "signature verify failed\n");
		loop_remove_io(loop, socket);
		closeSocket(socket);
		return -1;
	} else {
		pt[size] = 0;
		if (size >= 4) {
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
				fprintf(stderr, "REQ: %s\n", pt + 5);
				int fsize = -1;
				unsigned char *file_data = readFileAuto(full_path, &fsize);
				if ((file_data) && (fsize > 0)) {
					if (sendData(loop, host, socket, file_data, fsize, public_key, private_key, local_public_key, local_private_key, host->public_key, hash_table) <= 0)
						fprintf(stderr, "send error\n");
				}
				free(file_data);
			} else
			if (memcmp(pt, "DATA", 4) == 0) {
				writeFileAuto(pt + 5, size - 5);
			} else
			if (memcmp(pt, "LIST", 4) == 0) {
				char *list = (char *)pt + 5;
				char *line = list;
				while (line) {
					list = strchr(list, '\n');
					if (list) {
						list[0] = 0;
						list ++;

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
								int mode = 0;
								sscanf(mode_str, "%o", &mode);

								char request_data[MAX_PATH + 5];
								snprintf(full_path, sizeof(full_path), "%s/%s", root_path, path);

								int sync = 0;
								struct stat buf;
								if (lstat(full_path, &buf)) {
									if (((mode & S_IFMT) != S_IFDIR) || (mkdir(full_path, mode & ~S_IFMT)))
										sync = 1;
								} else {
									if (buf.st_mtime < mtime)
										sync = 1;
									else
									if (buf.st_mtime > mtime)
										sync = 2;

									if ((sync == 1) && ((buf.st_mode & S_IFMT) == S_IFDIR) && ((mode & S_IFMT) == S_IFDIR)) {
										struct utimbuf times;
										times.actime = mtime;
										times.modtime = mtime;

										utime(full_path, &times);
										sync = 0;
									}
								}

								switch (sync) {
									case 1:
										fprintf(stderr, "pull %s\n", path);
										snprintf(request_data, sizeof(request_data), "PULL\n%s", path);
										if (sendData(loop, host, socket, (const unsigned char *)request_data, strlen(request_data), public_key, private_key, local_public_key, local_private_key, host->public_key, hash_table) <= 0) {
											fprintf(stderr, "send error\n");
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

	if (connect(host->sock, (struct sockaddr *)&host->servaddr, sizeof(host->servaddr))) {
		perror("connect");
		fprintf(stderr, "error connecting to %s:%i\n", host->hostname, host->port);
		close(host->sock);
		host->sock = 0;
		return -1;
	}

	unsigned int size = htonl(32);
	addToBuffer(loop, host, host->sock, (unsigned char *)&size, sizeof(int));
	addToBuffer(loop, host, host->sock, local_public_key, 32);

	fprintf(stdout, "connected to %s:%i\n", host->hostname, host->port);

	loop_add_io_data(loop, host->sock, DOOPS_READWRITE, host);

	host->timestamp = time(NULL);
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

	fprintf(stderr, "carbonpaper v0.1 - real-time bidirectional directory synchronization tool\n(c)2023 by Eduard Suica (BSD-simplified license)\n\n");

	int path_index = 1;
	for (int i = 1; i < argc; i ++) {
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

				fprintf(stdout, "added host %s:%i\n", hosts[clients].hostname, hosts[clients].port);
				clients ++;
				path_index = i + 1;
			} else {
				fprintf(stderr, "--port: port number missing\n");
				exit(1);
			}
		}
	}

	if (path_index != argc - 1) {
		fprintf(stderr, "Usage: %s [options] path_to_sync\n\nAvailable options:\n\t--keygen path\tgenerate new network key in path\n\t--keypath path\tuse network keys in given path (default is current path)\n\t--port\t\tuse TCP port (default 4804)\n\n", argv[0]);
		exit(1);
	}

	if (loadFile(key_path, ".private_key", private_key, sizeof(private_key)) != sizeof(private_key)) {
		fprintf(stderr, "Error loading private key from [%s]\n\nTry using --genkey first.\n\n", key_path);
		exit(1);
	}

	if (loadFile(key_path, ".public_key", public_key, sizeof(public_key)) != sizeof(public_key)) {
		fprintf(stderr, "Error loading private key from [%s]\n\nTry using --genkey first.\n\n", key_path);
		exit(1);
	}

	if (genLocalKey(local_private_key, local_public_key)) {
		fprintf(stderr, "Error generating local key pair.\n\n", key_path);
		exit(1);
	}

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
	setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(int));

	if ((bind(server_socket, (struct sockaddr *)&servaddr, sizeof(servaddr))) != 0) {
		perror("bind");
		exit(0);
	}

	if (listen(server_socket, 1024)) {
		perror("listen");
		exit(0);
	}

	hash_table = kh_init(fd_to_name);

	scan_directory(fd, argv[path_index], hash_table);

	int absent;
	k = kh_put(fd_to_name, hash_table, wd, &absent);
	kh_value(hash_table, k) = strdup(argv[path_index]);

	signal(SIGPIPE, SIG_IGN);

	loop_init(&loop);

	loop_add_io(&loop, fd, DOOPS_READ);
	loop_add_io(&loop, server_socket, DOOPS_READ);

	root_path = argv[path_index];
	root_path_len = strlen(argv[path_index]);

	if (hosts) {
		loop_schedule(&loop, {
			int i;
			for (i = 0; i < clients; i ++) {
				if ((!hosts[i].sock) || (time(NULL) - hosts[i].timestamp >= 16)) {
					client_connect(loop, &hosts[i], local_public_key);
				} else {
					if (hosts[i].sock)
						sendData(loop, &hosts[i], hosts[i].sock, (const unsigned char *)"PING", 4, public_key, private_key, local_public_key, local_private_key, hosts[i].public_key, hash_table);
					if (hosts[i].sock_accept)
						sendData(loop, &hosts[i], hosts[i].sock_accept, (const unsigned char *)"PING", 4, public_key, private_key, local_public_key, local_private_key, hosts[i].public_key, hash_table);
				}
			}
		}, -4800);
	}

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
			int sent = send(sock, host->write_buffer, host->write_buffer_len, MSG_NOSIGNAL);
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
			int sent = send(sock, host->write_buffer_a, host->write_buffer_len_a, MSG_NOSIGNAL);
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
		char buffer[EVENT_BUF_LEN];
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
					fprintf(stdout, "accepted connection request\n");
					struct timeval tv;
					tv.tv_sec = 1;
					tv.tv_usec = 0;
					setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
					setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
					loop_add_io_data(loop, sock, DOOPS_READWRITE, host_data);
				} else {
					fprintf(stderr, "connection request from invalid address\n");
					close(sock);
				}
			}
		} else
		if (fd == inotify_fd) {
			int length = read(fd, buffer, EVENT_BUF_LEN); 
			consume(fd, buffer, length, hash_table);
		} else {
			receiveData(loop, fd, public_key, private_key, local_public_key, local_private_key, hash_table);
		}
    	});
	loop_run(&loop);
	loop_deinit(&loop);

	inotify_rm_watch(fd, wd);

	for (k = 0; k < kh_end(hash_table); ++k) {
		if (kh_exist(hash_table, k))
			free((char*)kh_value(hash_table, k));
	}

	free(hosts);

	kh_destroy(fd_to_name, hash_table);
	hash_table = NULL;

   	close(fd);
}
