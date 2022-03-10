#ifndef CORE_H
#define CORE_H

#include <list>
#include <vector>
#include <map>
#include <string>
#include <time.h>

#include <ortp/port.h>
#include <Packet.h>
#include <PcapLiveDeviceList.h>
using namespace pcpp;

#include <portaudio.h>

class Core
{
private:
	struct rtp_stream_t // 每路单向语音算一个流,以同步源区分，暂未合并双向语音
	{
		uint32_t ssrc;
		bool is_amr; // true:amr; false:amrwb
		uint16_t flag_port;
		std::string src_ip;
		std::string dst_ip;
		uint16_t src_port;
		uint16_t dst_port;
		
		FILE *f;
		uint16_t last_seq;
		uint32_t last_ts;
		time_t last_packet_time;

		bool stop_play;
		ortp_mutex_t mutex;
		ortp_mutex_t mutex2;
		ortp_thread_t play_thread;
		std::list<std::vector<uint8_t>> amr_frames;
		std::list<std::vector<int16_t>> pcm_frames;

		rtp_stream_t()
		{
			ssrc = 0;
			is_amr = true;
			flag_port = 0;

			src_ip = "";
			src_port = 0;
			dst_ip = "";
			dst_port = 0;

			f = NULL;
			last_seq = 0;
			last_ts = 0;
			last_packet_time = 0;

			stop_play = false;
			play_thread = 0;
			ortp_mutex_init(&mutex, NULL);
			ortp_mutex_init(&mutex2, NULL);
		}

		~rtp_stream_t()
		{
			if (play_thread != 0)
			{
				stop_play = true;
				ortp_thread_join(play_thread, NULL);
				play_thread = 0;
			}

			if (f != NULL)
			{
				fclose(f);
				f = NULL;
			}

			ortp_mutex_destroy(&mutex);
			ortp_mutex_destroy(&mutex2);
		}
	};

public:
    static Core& ins();
private:
    Core();
public:
    ~Core();

private:
	bool start_capture();

public:
    bool start();
    void stop();

private:
    static void* s_core_thread_func(void *data);
    int core_thread_func();

	static void s_OnPacketArrivesCallback(RawPacket* raw_packet, PcapLiveDevice* dev, void* udata);
	void process_packet(RawPacket* raw_packet);

	static void s_OnStatsUpdateCallback(IPcapDevice::PcapStats& stats, void* udata);
	void process_stats(IPcapDevice::PcapStats& stats);

	static int s_PaStreamCallback(const void *input, void *output, unsigned long frameCount, const PaStreamCallbackTimeInfo* timeInfo, PaStreamCallbackFlags statusFlags, void *userData);
	static void* s_play_thread_func(void *data);


private:
    bool m_request_quit;
	ortp_thread_t m_core_tid;
	ortp_mutex_t m_mutex;

	std::vector<rtp_stream_t*> m_streams;
};

#endif // CORE_H
