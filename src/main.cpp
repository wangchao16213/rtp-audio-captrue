
#include <stdio.h>
#include <stdlib.h>
#include <string>

#include "log.h"
#include "core.h"
#include "INIReader.h"


extern void sleep_ms(int ms);

void on_atexit()
{

	log_info("leave");
	log_uninit();
}

INIReader *conf_reader = NULL;
int main(int argc, char* argv[])
{
	::atexit(on_atexit);

	conf_reader = new INIReader("config.ini");

	if (conf_reader->ParseError() < 0)
	{
		fprintf(stderr, "Can't load 'config.ini'\n");
		return -1;
	}

	std::string log_file = conf_reader->Get("common", "log", "");

	int ret = log_init(LOG_DEBUG, log_file.c_str());
	if (ret != 0)
	{
		fprintf(stderr, "log_init fail\n");
		return -1;
	}
	log_info("enter");

	if (!Core::ins().start())
		return -1;


	for (int i = 0; 1; i++)
	{
		sleep_ms(1000);
		if (i % 60 == 0)
		{
			log_info("main thread alive");
		}
	}


	return 0;
}
