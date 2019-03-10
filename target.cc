
#include <atomic>
#include <future>
#include <iostream>
#include <thread>
#include <string>

#include <stddef.h>
#include <stdint.h>

#include <unistd.h>
#include <sys/socket.h>

extern "C" {

#include "libpomp.h"

}

std::atomic_bool m_isRunning;

static std::function<void (struct pomp_ctx *ctx, enum pomp_event event,
                    struct pomp_conn *conn, const struct pomp_msg *msg,
                    void *userdata)> m_lambdaServerCallback;

static std::function<void (struct pomp_ctx *ctx, enum pomp_event event,
                    struct pomp_conn *conn, const struct pomp_msg *msg,
                    void *userdata)> m_lambdaClientCallback;

static void server_event_cb(struct pomp_ctx *ctx, enum pomp_event event,
        struct pomp_conn *conn, const struct pomp_msg *msg,
        void *userdata)
    {
        m_lambdaServerCallback(ctx, event, conn, msg, userdata);
}

static void client_event_cb(struct pomp_ctx *ctx, enum pomp_event event,
        struct pomp_conn *conn, const struct pomp_msg *msg,
        void *userdata)
    {
        m_lambdaClientCallback(ctx, event, conn, msg, userdata);
}

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::promise<bool> m_server_connected;
    std::promise<bool> m_client_connected;
    struct pomp_loop * loop = pomp_loop_new();

    m_lambdaServerCallback = [&m_server_connected](struct pomp_ctx *ctx, enum pomp_event event,
                    struct pomp_conn *conn, const struct pomp_msg *msg,
                    void *userdata) {
                switch (event) {
                case POMP_EVENT_CONNECTED:
                    m_server_connected.set_value(true);
                    break;
                case POMP_EVENT_DISCONNECTED:
                    break;
                case POMP_EVENT_MSG:
                    break;
                }
            };

    m_lambdaClientCallback = [&m_client_connected](struct pomp_ctx *ctx, enum pomp_event event,
                    struct pomp_conn *conn, const struct pomp_msg *msg,
                    void *userdata) {
                switch (event) {
                case POMP_EVENT_CONNECTED:
                    m_client_connected.set_value(true);
                    break;
                case POMP_EVENT_DISCONNECTED:
                    break;
                case POMP_EVENT_MSG:
                    break;
                }
            };

    struct pomp_ctx * ctx_server = pomp_ctx_new_with_loop(&server_event_cb, NULL, loop);
    struct pomp_ctx * ctx_client = pomp_ctx_new_with_loop(&client_event_cb, NULL, loop);

    // 16 cause 2 * sizeof(struct sockaddr). In fact there are a mess in the library.
    // So to made it work on my computer I have to allocation a memory to the equals size except by the pomp_addr_parse method.
    struct sockaddr * addr = (struct sockaddr *) malloc(16);
    uint32_t addrlen = 16;

    const char * buff = "inet:127.0.0.1:5555";
    
    int res = pomp_addr_parse(buff, addr, &addrlen);

    res = pomp_ctx_listen(ctx_server, addr, addrlen);
    if (res < 0) {
        std::cerr << "ctx_server listen fail" << std::endl;
        return -1;
    }

    res = pomp_ctx_connect(ctx_client, addr, addrlen);
    if (res < 0) {
        std::cerr << "ctx_client connect fail" << std::endl;
        return -1;
    }

    std::thread t([&m_server_connected, &m_client_connected] {
        m_server_connected.get_future().wait();
        m_client_connected.get_future().wait();
        m_isRunning = false;
    });

    m_isRunning = true;

    while (m_isRunning) {
        pomp_loop_wait_and_process(loop, 10);
    }

    if (t.joinable()) {
        t.join();
    }
    
    pomp_ctx_stop(ctx_client);
    pomp_ctx_stop(ctx_server);
    pomp_ctx_destroy(ctx_client);
    pomp_ctx_destroy(ctx_server);
    pomp_loop_destroy(loop);

    free(addr);

    return 0;
}