#include "core.h"
#include "log.h"
#include <assert.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <UdpLayer.h>
#include <GtpLayer.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <ProtocolType.h>
#include <PcapLiveDeviceList.h>
#include <PcapFileDevice.h>

#include <dec_if.h>
#include <ortp/rtp.h>

#include "INIReader.h"

#include "wavwriter.h"
#include <dec_if.h>
#include <interf_dec.h>

#include <portaudio.h>
#include <windows.h>    /* required when using pa_win_wmme.h */
#include <mmsystem.h>   /* required when using pa_win_wmme.h */
#include "pa_win_wmme.h"
#include "pa_win_ds.h"
#include "pa_win_wasapi.h"

#define TEST_FILE 0

extern INIReader *conf_reader;

void sleep_ms(int ms)
{
	Sleep(ms);
}

extern void localtime3(tm *time, long *usec);

//  Change AMR and AMR-WB RTP Payload Formats to Storage Format
static bool rpf2sf(uint8_t *in, int ilen, uint8_t *out, int &olen, bool is_amr)
{
	// amr or amrwb in rtp format 
	/*
		The following diagram shows a bandwidth-efficient AMR payload from a
		single-channel session carrying a single speech frame-block.
		0                   1                   2                   3
		0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		| CMR=15|F| FT=4  |Q|d(0)                                       |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                                                               |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                                                               |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                                                               |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                                                     d(147)|P|P|
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/
	// amr or amrwb in file format
	/*
		The following example shows an AMR frame in 5.9 kbps coding mode
		(with 118 speech bits) in the storage format.

		0                   1                   2                   3
		0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|P| FT=2  |Q|P|P|                                               |
		+-+-+-+-+-+-+-+-+                                               +
		|                                                               |
		+          Speech bits for frame-block n, channel k             +
		|                                                               |
		+                                                           +-+-+
		|                                                           |P|P|
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		*/

		// write to  file
	const int amr_sizes[16] =	{ 12, 13, 15, 17, 19, 20, 26, 31, 5, 6, 5, 5, 0, 0, 0, 0 };
	const int amrwb_sizes[16] = { 17, 23, 32, 36, 40, 46, 50, 58, 60, 5, -1, -1, -1, -1, -1, 0 };
	int sizes[16];
	if (is_amr)
		memcpy(sizes, amr_sizes, sizeof(amr_sizes));
	else
		memcpy(sizes, amrwb_sizes, sizeof(amrwb_sizes));


	uint8_t ft = ((in[0] & 0x07) << 1) | ((in[1] >> 7) & 0x01);
	uint8_t q = (in[1] >> 6) & 0x01;

	if (ft <= 0) return false;

	memset(out, 0, olen);
	out[0] |= (ft << 3);
	out[0] |= (q << 2);
	int size = sizes[ft];
	if (size<=0)
	{
		ft = 15;
		size = 0;
	}
	for (int i = 1; i < size; i++)
	{
		out[i] = (in[i] << 2) | ((in[i + 1] >> 6) & 0x3f);
	}
	olen = size + 1;

	return true;
}

class local_lock
{
public:
	local_lock(ortp_mutex_t &mutex) :m_mutex(mutex)
	{
		ortp_mutex_lock(&mutex);
	}
	~local_lock()
	{
		ortp_mutex_unlock(&m_mutex);
	}

private:
	ortp_mutex_t &m_mutex;
};

Core &Core::ins()
{
    static Core obj;
    return obj;
}

Core::Core()
{
    m_request_quit = false;
    m_core_tid = 0;
	ortp_mutex_init(&m_mutex, NULL);
}

Core::~Core()
{
    stop();
	ortp_mutex_destroy(&m_mutex);
}

bool Core::start_capture()
{
	std::string eth = conf_reader->Get("common", "eth", "");
	if (eth.empty())
	{
		log_error("config eth empty");
		return false;
	}

	WinPcapLiveDevice* dev = (WinPcapLiveDevice*)PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(eth);
	if (dev == NULL)
	{
		std::replace(eth.begin(), eth.end(), '-', ':');
		std::transform(eth.begin(), eth.end(), eth.begin(), std::tolower);

		const std::vector<PcapLiveDevice*> devs = PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
		for (int i = 0; i < devs.size(); i++)
		{
			std::string addr = devs[i]->getMacAddress().toString();
			if (devs[i]->getMacAddress().toString() == eth)
			{
				dev = (WinPcapLiveDevice*)devs[i];
			}
		}

		if (dev == NULL)
		{
			log_error("Couldn't find interface by provided IP address or mac address");
			return false;
		}
	}


	if (!dev->open())
	{
		log_error("dev->open fail");
		return false;
	}

	//uint16_t gtp_port = conf_reader->GetInteger("common", "gtp_port", 2152);
	uint16_t rtp_port = conf_reader->GetInteger("common", "rtp_port", 3001);

	pcpp::OrFilter filter;
	//filter.addFilter(new pcpp::PortFilter(gtp_port, pcpp::SRC_OR_DST));
	filter.addFilter(new pcpp::PortFilter(rtp_port, pcpp::SRC_OR_DST));

	// this port for debug
	//filter.addFilter(new pcpp::PortFilter(53, pcpp::SRC_OR_DST));

	if (!dev->setFilter(filter))
	{
		log_error("dev->setFilter fail");
		return false;
	}

	if (!dev->startCapture(Core::s_OnPacketArrivesCallback, this, 60, Core::s_OnStatsUpdateCallback, this))
	{
		log_error("dev->startCapture fail");
		return false;
	}

	return true;
}


bool Core::start()
{

    m_request_quit = false;

    ortp_thread_t tid = 0;

    if (ortp_thread_create(&tid, NULL, s_core_thread_func, NULL)!=0)
    {
        log_fatal("create thread fail");
        return false;
    }
    m_core_tid = tid;

	log_info("portaudio version=%s", Pa_GetVersionText());

	PaError err = Pa_Initialize();
	if (err != paNoError)
	{
		log_fatal("Pa_Initialize fail. %s", Pa_GetErrorText(err));
		return false;
	}
	log_info("Pa_Initialize ok");
	

#if TEST_FILE
	// test
	pcpp::PcapFileReaderDevice reader("amrwb.pcap");
	if (!reader.open())
	{
		log_error("Error opening the pcap file\n");
		return false;
	}

	uint16_t rtp_port = conf_reader->GetInteger("common", "rtp_port", 3001);
	pcpp::PortFilter filter(rtp_port, pcpp::SRC_OR_DST);
	reader.setFilter(filter);

	// read packets and parse
	pcpp::RawPacket raw_packet;
	for (int i=0; reader.getNextPacket(raw_packet); i++)
	{
		if (i%10==0)
			sleep_ms(100);

		s_OnPacketArrivesCallback(&raw_packet, NULL, this);
	}
	reader.close();
#else

	if (!start_capture())
		return false;

#endif // TEST_FILE

	log_info("ok");
    return true;
}

void Core::stop()
{
    m_request_quit = true;

    if (m_core_tid !=0)
    {
        ortp_thread_join(m_core_tid, NULL);
        m_core_tid = 0;
    }

	for (int i = 0; i < m_streams.size(); i++)
	{
		delete m_streams[i];
	}
	m_streams.clear();

	Pa_Terminate();
	log_info("Pa_Terminate ok");

    log_info("ok");
}




void *Core::s_core_thread_func(void *data)
{
    log_info("enter");
    Core::ins().core_thread_func();
    log_info("leave");
    return NULL;
}


int Core::core_thread_func()
{

	for (;!m_request_quit;)
	{
		sleep_ms(2000);

		// check for stream timeout
		ortp_mutex_lock(&m_mutex);
		int timeout = conf_reader->GetInteger("common", "timeout", 20);
		time_t tm = time(NULL);
		for (std::vector<rtp_stream_t*>::iterator it=m_streams.begin(); it!=m_streams.end();)
		{
			rtp_stream_t *s = *it;
			if (tm - s->last_packet_time >= timeout)
			{
				it = m_streams.erase(it);
				uint32_t ssrc = s->ssrc;
				delete s;
				log_debug("stream %08x timeout for %ds, stopped", ssrc, timeout);
			}
			else
			{
				++it;
			}
		}
		
		ortp_mutex_unlock(&m_mutex);
	}

    return 0;
}

void Core::s_OnPacketArrivesCallback(RawPacket* raw_packet, PcapLiveDevice* dev, void* udata)
{
	Core *obj = (Core*)udata;
	if (obj == NULL || raw_packet == NULL) return;
	obj->process_packet(raw_packet);
}

void Core::process_packet(RawPacket* raw_packet)
{
	assert(raw_packet != NULL);
	// parse the raw packet into a parsed packet
	pcpp::Packet parsed_packet(raw_packet);

	// verify the packet is IPv4
	if (!parsed_packet.isPacketOfType(pcpp::IP) || !parsed_packet.isPacketOfType(pcpp::UDP))
		return;

	// extract source and dest IPs
	std::string src_ip = parsed_packet.getLayerOfType<pcpp::IPLayer>()->getSrcIPAddress().toString();
	std::string dst_ip = parsed_packet.getLayerOfType<pcpp::IPLayer>()->getDstIPAddress().toString();
	uint16_t  dest_port = parsed_packet.getLayerOfType<pcpp::UdpLayer>()->getDstPort();
	uint16_t  src_port = parsed_packet.getLayerOfType<pcpp::UdpLayer>()->getSrcPort();

	uint16_t flag_port = dest_port;

	rtp_header_t *rtp = NULL;
	int rtp_packet_size = 0;

	//uint16_t gtp_port = conf_reader->GetInteger("common", "gtp_port", 2152);
	uint16_t rtp_port = conf_reader->GetInteger("common", "rtp_port", 3001);

	if (dest_port == rtp_port || src_port == rtp_port)
	{
		// udp payload == 48bytes other info + rtp packet

		uint8_t *payload = parsed_packet.getLayerOfType<pcpp::UdpLayer>()->getLayerPayload();
		size_t psize = parsed_packet.getLayerOfType<pcpp::UdpLayer>()->getLayerPayloadSize();
		rtp = (rtp_header_t *)(payload + 48);
		rtp_packet_size = psize - 48;
	}
#if 0
	else if (dest_port == gtp_port || src_port == gtp_port)
	{
		pcpp::GtpV1Layer *gtp_layer = parsed_packet.getLayerOfType<pcpp::GtpV1Layer>();
		if (gtp_layer == NULL) return;
		pcpp::Layer *ip_layer = gtp_layer->getNextLayer();
		if (ip_layer != NULL && ip_layer->getProtocol() == pcpp::IPv6)
		{
			src_ip = ((pcpp::IPv6Layer*)ip_layer)->getSrcIPAddress().toString();
			dst_ip = ((pcpp::IPv6Layer*)ip_layer)->getDstIPAddress().toString();

			pcpp::Layer *udp_layer = ip_layer->getNextLayer();
			if (udp_layer != NULL && udp_layer->getProtocol() == pcpp::UDP)
			{
				src_port = ((pcpp::UdpLayer*)udp_layer)->getSrcPort();
				dest_port = ((pcpp::UdpLayer*)udp_layer)->getDstPort();

				rtp = (rtp_header_t *)(udp_layer->getLayerPayload());
				rtp_packet_size = udp_layer->getLayerPayloadSize();
			}
		}
	}
#endif
	else
	{
		return;
	}

	if (rtp == NULL || rtp_packet_size <= 0) return;

	int is_amr = -1; // -1:null, 0:amrwb; 1:amr
	//if (rtp->paytype == 108 || rtp->paytype == 105 || rtp->paytype == 104 || rtp->paytype == 103 || rtp->paytype == 102)
	//	is_amr = 1;
	//else if (rtp->paytype == 107 || rtp->paytype == 106)
	//	is_amr = 0;
	//else
	//	is_amr = -1;
	char payload[32] = { 0 };
	sprintf(payload, "%d", rtp->paytype);
	std::string amrstr = conf_reader->Get("common", "amr", "");
	std::string amrwbstr = conf_reader->Get("common", "amrwb", "");

	const char *p = strtok((char*)amrstr.data(), ",");
	while (p != NULL)
	{
		if (strcmp(p, payload) == 0)
		{
			is_amr = 1;
			break;
		}
		p = strtok(NULL, ",");
	}

	if (is_amr == -1)
	{
		const char *p = strtok((char*)amrwbstr.data(), ",");
		while (p != NULL)
		{
			if (strcmp(p, payload) == 0)
			{
				is_amr = 0;
				break;
			}
			p = strtok(NULL, ",");
		}
	}

	if (rtp->version != 2 || is_amr==-1) return;

	/* convert all header data from network order to host order */
	rtp->seq_number = ntohs(rtp->seq_number);
	rtp->timestamp = ntohl(rtp->timestamp);
	rtp->ssrc = ntohl(rtp->ssrc);


	uint8_t frame[64] = { 0 };
	int flen = sizeof(frame);
	int rtp_header_len = 12;
	if (!rpf2sf((uint8_t*)rtp + rtp_header_len, rtp_packet_size - rtp_header_len, frame, flen, is_amr))
		return;

	local_lock m(m_mutex);
	// find stream by the ssrc 
	rtp_stream_t *s = NULL;
	for (int i = 0; i < m_streams.size(); i++)
	{
		if (rtp->ssrc == m_streams[i]->ssrc)
		{
			s = m_streams[i];
			break;
		}
	}

	if (s == NULL)
	{
		//if (m_streams.size() > 0) return;
		s = new rtp_stream_t;
		s->ssrc = rtp->ssrc;
		s->is_amr = is_amr;
		s->flag_port = flag_port;
		s->src_ip = src_ip;
		s->dst_ip = dst_ip;
		s->src_port = src_port;
		s->dst_port = dest_port;
		s->last_seq = rtp->seq_number;
		s->last_ts = rtp->timestamp;
		s->last_packet_time = time(NULL);

		char name[1024] = { 0 };
		struct tm time = *localtime(&(s->last_packet_time));

		// if ipv6, replace "::" to "." for file name
		std::replace(src_ip.begin(), src_ip.end(), ':', '.');
		std::replace(dst_ip.begin(), dst_ip.end(), ':', '.');

		::CreateDirectoryA("tone", NULL);

		snprintf(name, sizeof(name) - 1, "tone/%d_%i-%.2i-%.2i-%.2i-%.2i-%.2i_%08x_%s-%s.amr", flag_port,
			1900 + time.tm_year, 1 + time.tm_mon, time.tm_mday, time.tm_hour, time.tm_min, time.tm_sec,
			rtp->ssrc, src_ip.c_str(), dst_ip.c_str());

		s->f = fopen(name, "wb");
		if (s->f == NULL)
		{
			log_warn("stream %08x, open file error, %s", s->ssrc, name);
			return;
		}
		
		if (s->is_amr)
		{
			const char *header = "#!AMR\n";
			fwrite(header, 1, strlen(header), s->f);
		}
		else
		{
			const char *header = "#!AMR-WB\n";
			fwrite(header, 1, strlen(header), s->f);
		}

		ortp_thread_t tid = 0;
		if (ortp_thread_create(&tid, NULL, s_play_thread_func, s) != 0)
		{
			log_fatal("stream %08x, ortp_thread_create fail", s->ssrc);
			return;
		}
		s->play_thread = tid;

		m_streams.push_back(s);
		log_debug("stream %08x started", s->ssrc);
	}
	else
	{
		// discard duplicate packets
		if (rtp->seq_number == s->last_seq ||
			rtp->timestamp == s->last_ts)
		{
			return;
		}
		s->last_seq = rtp->seq_number;
		s->last_ts = rtp->timestamp;
		s->last_packet_time = time(NULL);
	}

	if (s->f != NULL)
	{
		fwrite(frame, 1, flen, s->f);
	}

	ortp_mutex_lock(&s->mutex);
	s->amr_frames.push_back(std::vector<uint8_t>(frame, frame + flen));
	ortp_mutex_unlock(&s->mutex);
}

void Core::s_OnStatsUpdateCallback(IPcapDevice::PcapStats& stats, void* udata)
{
	Core *obj = (Core*)udata;
	if (obj == NULL) return;
	obj->process_stats(stats);
}

void Core::process_stats(IPcapDevice::PcapStats& stats)
{
	log_debug("stats.packetsRecv=%lu, stats.packetsDrop=%lu", stats.packetsRecv, stats.packetsDrop);
}

 int Core::s_PaStreamCallback(
	const void *input, void *output,
	unsigned long samples_per_frame,
	const PaStreamCallbackTimeInfo* timeInfo,
	PaStreamCallbackFlags statusFlags,
	void *userData)
{
	 assert(userData != NULL);
	 rtp_stream_t *s = (rtp_stream_t*)userData;

	 if (s->stop_play)
		 return paComplete;

	 //if (statusFlags != 0)
	 //{
		// log_debug("statusFlags=%d", statusFlags);
	 //}
	 //if (frameCount == 0)
	 //{
	//	 log_debug("samples_per_frame==%lu", samples_per_frame);
	 //}

	 std::vector<int16_t> frame;
	 ortp_mutex_lock(&s->mutex2);
	 if (!s->pcm_frames.empty())
	 {
		 frame = s->pcm_frames.front();
		 s->pcm_frames.pop_front();
	 }
	 ortp_mutex_unlock(&s->mutex2);

	 

	 if (output != NULL)
	 {
		 if (frame.empty())
		 {
			 // silent data
			 memset(output, 0, samples_per_frame * 2);
			// log_debug("stream %08x", s->ssrc);
		 }
		 else
			memcpy(output, frame.data(), samples_per_frame * 2);
	 }

	 return paContinue;
}

void* Core::s_play_thread_func(void *data)
{
	assert(data != NULL);
	rtp_stream_t *s = (rtp_stream_t*)data;
	log_info("stream %08x, enter", s->ssrc);

	void *dec;
	if (s->is_amr)
		dec = Decoder_Interface_init();
	else
		dec = D_IF_init();
	
	if (dec == NULL)
	{
		log_fatal("stream %08x, D_IF_init or Decoder_Interface_init fail", s->ssrc);
		return NULL;
	}

	int samplerate=0;
	int samples_per_frame=0;
	if (s->is_amr)
	{
		samplerate = 8000;
	}
	else
	{
		samplerate = 16000;
	}
	samples_per_frame = samplerate / 50; // one frame 20ms

	PaStreamParameters outputParameters;
	outputParameters.device = Pa_GetDefaultOutputDevice(); 
	//outputParameters.device = Pa_GetHostApiInfo(Pa_HostApiTypeIdToHostApiIndex(paMME))->defaultOutputDevice;
	if (outputParameters.device == paNoDevice)
	{
		log_error("stream %08x, Error: No default output device.", s->ssrc);
		return NULL;
	}
	outputParameters.channelCount = 1;       
	outputParameters.sampleFormat = paInt16; 
	outputParameters.suggestedLatency = Pa_GetDeviceInfo(outputParameters.device)->defaultLowOutputLatency;
	outputParameters.hostApiSpecificStreamInfo = NULL;

	//PaWinMmeStreamInfo wmmeStreamInfo;
	//wmmeStreamInfo.size = sizeof(PaWinMmeStreamInfo);
	//wmmeStreamInfo.hostApiType = paMME;
	//wmmeStreamInfo.version = 1;
	////wmmeStreamInfo.flags = paWinMmeUseLowLevelLatencyParameters;
	////wmmeStreamInfo.channelMask = PAWIN_SPEAKER_FRONT_CENTER;
	//outputParameters.hostApiSpecificStreamInfo = &wmmeStreamInfo;

	//PaWinDirectSoundStreamInfo streamInfo;
	//streamInfo.size = sizeof(PaWinDirectSoundStreamInfo);
	//streamInfo.hostApiType = paDirectSound;
	//streamInfo.version = 2;
	//streamInfo.flags = 0;
	//streamInfo.channelMask = PAWIN_SPEAKER_FRONT_CENTER;
	//outputParameters.hostApiSpecificStreamInfo = &streamInfo;

	PaStream *stream = NULL;
	PaError err = Pa_OpenStream(
		&stream,
		NULL, /* no input */
		&outputParameters,
		samplerate,
		samples_per_frame,
		paNoFlag,
		s_PaStreamCallback,
		s );
	if (err != paNoError)
	{
		log_error("stream %08x, Pa_OpenStream fail, %s", s->ssrc, Pa_GetErrorText(err));
		return NULL;
	}
	
	err = Pa_StartStream(stream);
	if (err != paNoError)
	{
		log_error("stream %08x, Pa_StartStream fail, %s", s->ssrc, Pa_GetErrorText(err));
		return NULL;
	}

	int frame_count = 0;
	while (!s->stop_play)
	{
		ortp_mutex_lock(&s->mutex);
		std::vector<std::vector<uint8_t>> amr_frames(s->amr_frames.begin(), s->amr_frames.end());
		s->amr_frames.clear();
		ortp_mutex_unlock(&s->mutex);

		if (amr_frames.size() == 0)
		{
			if (!Pa_IsStreamActive(stream))
			{
				Pa_StopStream(stream);
				err = Pa_StartStream(stream);
				if (err != paNoError)
				{
					log_error("stream %08x, restart Pa_StartStream fail, %s", s->ssrc, Pa_GetErrorText(err));
					return NULL;
				}
			}

			sleep_ms(1);
			continue;
		}

		std::vector<std::vector<int16_t>> pcm_frames;

		for (int i = 0; i < amr_frames.size(); i++)
		{
			std::vector<uint8_t> &frame = amr_frames[i];

			/* Decode the packet */
			int16_t pcm[320] = { 0 };
			if (s->is_amr)
			{
				Decoder_Interface_Decode(dec, frame.data(), pcm, 0);
			}
			else
			{
				D_IF_decode(dec, frame.data(), pcm, 0);
			}

			pcm_frames.push_back(std::vector<int16_t>(pcm, pcm + samples_per_frame));

			// use callback
			//err = Pa_WriteStream(stream, pcm, samples_per_frame);
			//if (err != paNoError)
			//{
			//	//log_warn("stream %08x, Pa_WriteStream fail, %s", s->ssrc, Pa_GetErrorText(err));
			//	//return NULL;
			//	err = Pa_WriteStream(stream, pcm, samples_per_frame);
			//	if (err != paNoError)
			//	{
			//		log_warn("stream %08x, Pa_WriteStream fail, %s", s->ssrc, Pa_GetErrorText(err));
			//	}
			//}
			frame_count++;
		}
		amr_frames.clear();

		if (pcm_frames.size() > 0)
		{
			ortp_mutex_lock(&s->mutex2);
			s->pcm_frames.insert(s->pcm_frames.end(), pcm_frames.begin(), pcm_frames.end());
			ortp_mutex_unlock(&s->mutex2);
			pcm_frames.clear();
			//log_debug("stream %08x", s->ssrc);
		}
	}

	if (s->is_amr)
		Decoder_Interface_exit(dec);
	else
		D_IF_exit(dec);

	Pa_StopStream(stream);
	Pa_CloseStream(stream);

	log_info("stream %08x, frame_count=%d", s->ssrc, frame_count);
	log_info("stream %08x, leave", s->ssrc);
	return NULL;
}

