/*
 * main_sec_no_reordering.c
 * Lock and unlock rhythmically between receiving threads and processing threads (one report coming, one report going).
 *  Created on: Nov 29, 2016
 *      Author: vinh
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "lib/dpi_message_t.h"
#include "lib/mmt_smp_security.h"

#define MAX_RULE_MASK_SIZE 100000
//maximum length of a report sent from mmt-probe
#define REPORT_SIZE 10000
//maximum length of file name storing alerts
#define MAX_FILENAME_SIZE 500

#define MMT_SEC_MSG_DATA_TYPE_STRING 1
#define MMT_SEC_MSG_DATA_TYPE_BINARY   2

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif

//print out detailed message
static bool verbose                     = NO;
static mmt_sec_handler_t *sec_handler   = NULL;
static size_t proto_atts_count          = 0;
const proto_attribute_t *const *proto_atts    = NULL;
//id of the listening socket of the parent
static int socket_server                = -1;
//id of the connected socket of the child serving it (-1 in the parent)
static int socket_client                = -1;
//set by the signal handler: the accept loop of the parent and the read loop
//of each child then stop and run termination() on their own thread
static volatile sig_atomic_t is_interrupted = 0;

static char output_file_string[MAX_FILENAME_SIZE + 1]  = {0};
static char output_redis_string[MAX_FILENAME_SIZE + 1] = {0};
static size_t reports_count = 0;
static size_t clients_count = 0;
static struct timeval start_time, end_time;

static inline double time_diff(struct timeval t1, struct timeval t2) {
	return (double)(t2.tv_sec - t1.tv_sec) + (t2.tv_usec - t1.tv_usec)/1000000.0;
}

void usage(const char * prg_name) {
	fprintf(stderr, "MMT-Security version %s\n",  mmt_sec_get_version_info() );
	fprintf(stderr, "%s [<option>]\n", prg_name);
	fprintf(stderr, "Option:\n");
	fprintf(stderr, "\t-p <number/string> : If p is a number, it indicates port number of internet domain socket otherwise it indicates name of unix domain socket. Default: 5000\n");
	fprintf(stderr, "\t-n <number> : Number of threads per process. Default = 1\n");
	fprintf(stderr, "\t-c <string> : Gives the range of logical cores to run on, e.g., \"1,3-8,16\"\n");
	fprintf(stderr, "\t-x <string> : Gives the range of rules id to be excluded from verification, e.g., \"1,3-8,16\"\n");
	fprintf(stderr, "\t-m <string> : Attributes special rules to special threads e.g., \"(1:10-13)(2:50)(4:1007-1010)\"\n");
	fprintf(stderr, "\t            : A value of 100000 or more in a -c, -x or -m range is rejected with an error:\n");
	fprintf(stderr, "\t              the mask parser uses a table of 100000 entries; before, a range reaching\n");
	fprintf(stderr, "\t              that bound could write past it.\n");
	fprintf(stderr, "\t-f <string> : Output results to file, e.g., \"/home/tata/:5\" => output to folder /home/tata and each file contains reports during 5 seconds \n");
	fprintf(stderr, "\t-r <string> : Output results to redis, e.g., \"localhost:6379\"\n");
	fprintf(stderr, "\t-v          : Verbose.\n");
	fprintf(stderr, "\t-l          : Prints the available rules then exit.\n");
	fprintf(stderr, "\t-h, --help  : Prints this help.\n");
	//does not exit: -h exits with success, a usage error with failure
}

size_t parse_options(int argc, char ** argv, uint16_t *port_no, char *unix_domain, size_t *threads_count,
		size_t *cores_count, uint32_t **core_mask, char *excluded_rules_mask, char *rule_mask, bool *verbose ) {
	int opt, optcount = 0, x;
	static const struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};
	excluded_rules_mask[0] = '\0';
	rule_mask[0]           = '\0';
	while ((opt = getopt_long(argc, argv, "p:n:f:r:c:m:x:vlbh", long_opts, NULL)) != EOF) {
		switch (opt) {
		case 'p':
			optcount++;

			x = atoi( optarg );
			*port_no = x;
			if( x == 0 ){
				strncpy((char *) unix_domain, optarg, MAX_FILENAME_SIZE);
			}
			break;
		case 'f':
			optcount++;
			strncpy((char *) output_file_string, optarg, MAX_FILENAME_SIZE);
			break;
		case 'r':
			optcount++;
			strncpy((char *) output_redis_string, optarg, MAX_FILENAME_SIZE);
			break;
		case 'n':
			optcount++;
			if (optcount < 1) {
				usage(argv[0]);
				exit(1);
			}
			x = atoi( optarg );
			if( x >= 0 )
				*threads_count = x;
			else{
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'm':
			optcount++;
			strncpy( rule_mask, optarg, MAX_RULE_MASK_SIZE );
			break;
		case 'x':
			optcount++;
			strncpy( excluded_rules_mask, optarg, MAX_RULE_MASK_SIZE );
			break;
		case 'c':
			optcount++;
			*cores_count = expand_number_range( optarg, core_mask );
			if( *cores_count == 0 ){
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'l':
			mmt_sec_init( excluded_rules_mask );
			mmt_sec_print_rules_info();
			mmt_sec_close();
			exit( 0 );
		case 'b':
			optcount++;
			//Keep for future use
			break;
		case 'v':
			optcount++;
			*verbose = YES;
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
		default:
			usage(argv[0]);
			exit(1);
		}
	}
	return 0;
}


static inline int _get_dpi_data_type( uint32_t proto_id, uint32_t att_id ){
	size_t i;
	for( i=0; i<proto_atts_count; i++ )
		if( proto_atts[ i ]->proto_id == proto_id && proto_atts[ i ]->att_id == att_id ){
			return proto_atts[ i ]->dpi_type;
		}

#ifdef DEBUG_MODE
//	mmt_warn( "Unknown data type of attribute %"PRIu32" of protocol %"PRIu32, att_id, proto_id );
#endif

	return -1;
}

/* On the wire an element's data occupies data_length bytes. For the types
 * whose conversion reads fixed-size fields, data_length must cover their
 * size. For the variable-length types, the first 4 bytes are a number of
 * items and the items that follow must fit in data_length. Returns 0 when
 * data_length cannot encode a valid value of dpi_data_type. */
static inline int _element_data_fits( int dpi_data_type, const uint8_t *data, uint16_t data_length ){
	uint32_t items_count, item_size;
	switch( dpi_data_type ){
	case MMT_DATA_CHAR:
	case MMT_U8_DATA:
		return data_length >= 1;
	case MMT_DATA_PORT:
	case MMT_U16_DATA:
		return data_length >= 2;
	case MMT_U32_DATA:
	case MMT_DATA_FLOAT:
	case MMT_DATA_IP_NET:
	case MMT_DATA_IP_ADDR:
		return data_length >= 4;
	case MMT_DATA_MAC_ADDR:
		return data_length >= 6;
	case MMT_U64_DATA:
		return data_length >= 8;
	case MMT_DATA_IP6_ADDR:
	case MMT_DATA_TIMEVAL:
		return data_length >= sizeof( struct timeval );
	//the variable-length types start with a uint32 number of items:
	// a byte count for strings and binary data, an entry count otherwise
	case MMT_STRING_DATA:
	case MMT_STRING_LONG_DATA:
	case MMT_BINARY_DATA:
	case MMT_BINARY_VAR_DATA:
		item_size = 1;
		break;
	case MMT_U16_ARRAY:
		item_size = 2;
		break;
	case MMT_U32_ARRAY:
	case MMT_DATA_PATH:
		item_size = 4;
		break;
	case MMT_U64_ARRAY:
		item_size = 8;
		break;
	//the other types read nothing from the element
	default:
		return 1;
	}
	if( data_length < sizeof( items_count ))
		return 0;
	memcpy( &items_count, data, sizeof( items_count ));
	return items_count <= ( data_length - sizeof( items_count )) / item_size;
}

/**
 * Received reports from mmt-probe.
 * For each incoming report, the function will converts them to a #message_t type,
 *  then passes it to #mmt_security
 */
static inline size_t receiving_reports( int sock ) {
	size_t index;
	ssize_t n;
	uint8_t buffer[ REPORT_SIZE ], *buf_ptr; //utf-8

	uint32_t length_of_report = 0;
	message_t *msg;
	uint32_t proto_id, att_id;
	uint16_t data_length;
	int dpi_data_type;
	size_t counter;
	size_t elements_count;
	struct timeval timestamp;

	reports_count = 0;
	while( ! is_interrupted ){

		//Read 4 bytes first to know the length of the report
		n = recv( sock, &length_of_report, 4, MSG_WAITALL );

		//end of socket flow, the socket was shut down by the signal
		//handler, or the peer stopped inside the length itself
		if ( unlikely( n != 4 ))	break;

		//the length includes its own 4 bytes: a shorter value has no body
		//and nothing to skip, so the rest of the stream still parses
		if( unlikely( length_of_report < 4 )){
			mmt_warn( "Invalid length_of_report = %"PRIu32, length_of_report );
			continue;
		}

		//a report cannot be bigger than buffer: there is no way to
		//resynchronize the stream after it, so the connection is dropped
		if( unlikely( length_of_report > REPORT_SIZE + 4 )){
			mmt_warn( "Invalid length_of_report = %"PRIu32, length_of_report );
			break;
		}

		n = recv( sock, buffer, length_of_report-4, MSG_WAITALL );

		//a report must be received in full: a short read leaves the stream
		// without a resynchronization point, so the connection is dropped
		if( unlikely( n != (ssize_t)( length_of_report - 4 ))){
			if( ! is_interrupted )
				mmt_warn( "Incomplete report: expected %"PRIu32" bytes, received %zd", length_of_report - 4, n );
			break;
		}

		//a report needs at least the elements count and the timestamp
		if( unlikely( n < (ssize_t)( 1 + sizeof( timestamp )))){
			mmt_warn( "Malformed report of %zd bytes", n );
			continue;
		}

		index = 0;

		//parser data
		//number of elements
		elements_count = (uint8_t) buffer[ index ];
		index += 1;

		msg = create_message_t();

		//the timestamp sits at index=1 in the packed report: read it with
		//memcpy instead of casting, the buffer has no alignment (fork #66)
		memcpy( &timestamp, &buffer[index], sizeof( timestamp ));
		msg->timestamp = mmt_sec_encode_timeval( &timestamp );
		index += sizeof (struct timeval);//16

		msg->counter = reports_count; //TODO

		for(counter = 0; counter < elements_count; counter ++){
			//an element is proto_id(4) att_id(4) data_length(2) then data
			if( unlikely( index + 10 > (size_t) n )){
				mmt_warn( "Malformed report of %zd bytes: truncated element header at %zu", n, index );
				goto drop_report;
			}

			//protocol ID
			//proto_id = *(uint32_t *) &buffer[index];
			memcpy( &proto_id, &buffer[index], 4 );
			index += 4;

			//attribute ID
			//att_id = *(uint32_t*) &buffer[index];
			memcpy( &att_id, &buffer[index], 4 );
			index += 4;

			//data length
			//data_length = *(uint16_t *) &buffer[index];
			memcpy( &data_length, &buffer[index], 2 );
			index += 2;

			//the element's data must be inside the received report
			if( unlikely( index + data_length > (size_t) n )){
				mmt_warn( "Malformed report of %zd bytes: data of element %zu is out of range", n, counter );
				goto drop_report;
			}

			dpi_data_type = _get_dpi_data_type( proto_id, att_id );
			//an attribute that no loaded rule uses is not registered: it
			//is skipped, like dpi_message_set_dpi_data did before
			if( unlikely( dpi_data_type < 0 )){
				index += data_length;
				continue;
			}
			if( unlikely( ! _element_data_fits( dpi_data_type, &buffer[index], data_length ))){
				mmt_warn( "Malformed data of attribute %"PRIu32".%"PRIu32" in report", proto_id, att_id );
				goto drop_report;
			}

			//data
			//special processing for these data types
			switch( dpi_data_type ){
			case MMT_STRING_DATA_POINTER:
			case MMT_GENERIC_HEADER_LINE :
			case MMT_HEADER_LINE :
				set_element_data_message_t( msg, proto_id, att_id,  &buffer[index], MMT_SEC_MSG_DATA_TYPE_STRING, data_length );
				break;
			case MMT_DATA_POINTER:
				set_element_data_message_t( msg, proto_id, att_id,  &buffer[index], MMT_SEC_MSG_DATA_TYPE_BINARY, data_length );
				break;
			//the variable-length types are encoded as a number of items
			//then the items: store the element as received rather than the
			//fixed-size struct dpi_message_set_dpi_data reads for in-memory
			//data
			case MMT_BINARY_DATA:
			case MMT_BINARY_VAR_DATA:
			case MMT_U16_ARRAY:
			case MMT_U32_ARRAY:
			case MMT_U64_ARRAY:
			case MMT_DATA_PATH:
				set_element_data_message_t( msg, proto_id, att_id,  &buffer[index], MMT_SEC_MSG_DATA_TYPE_BINARY, data_length );
				break;
			default:
				dpi_message_set_dpi_data( &buffer[index], dpi_data_type, msg, proto_id, att_id );
			}
			index += data_length;
		}

		reports_count ++;
		//call mmt_security
		mmt_sec_process( sec_handler, msg );
		continue;

	//a malformed report is not processed: it was received in full, so the
	//stream stays synchronized and the next report still parses
	drop_report:
		free_message_t( msg );
	}

	return reports_count;
}

static inline size_t termination(){
	size_t alerts_count = 0;
	if( sec_handler != NULL ){
		alerts_count = mmt_sec_unregister( sec_handler );
	}
	sec_handler = NULL;

	mmt_sec_close();
	return alerts_count;
}


void signal_handler_seg(int signal_type) {
	mmt_error( "Interrupted by signal %d", signal_type );

	close( socket_server );
	mmt_print_execution_trace();
	usleep( 50 );
	exit( signal_type );
}

//The handler only sets is_interrupted and wakes the accept/recv loops: the
//whole termination - mmt_smp_sec_process( NULL ) to insert the NULL markers
//then pthread_join of the workers - used to run inside it, which is not
//async-signal-safe and deadlocked when the signal landed on a worker thread
//of a child (the handler spins on the ring whose consumer is suspended in
//the handler, or joins itself). termination() now runs on the main thread of
//the parent and of each child, which notice is_interrupted in their loops
//(Montimage fork #31, E3).
void signal_handler(int signal_type) {
	static volatile int times_counter = 0;

	//a second signal exits immediately (e.g. Ctrl+c twice)
	if( times_counter >= 1 ) exit( signal_type );
	times_counter ++;

	is_interrupted = 1;
	//async-signal-safe wakeups: shutdown() unblocks a recv() blocked in
	//another thread; on the thread that ran the handler, accept() and recv()
	//also return EINTR as register_signals() does not set SA_RESTART
	if( socket_server >= 0 )
		shutdown( socket_server, SHUT_RDWR );
	if( socket_client >= 0 )
		shutdown( socket_client, SHUT_RDWR );
}


void register_signals(){
	struct sigaction sa;
#ifndef DEBUG_MODE
	signal(SIGSEGV, signal_handler_seg );
#endif
	//no SA_RESTART: a signal interrupts the accept() of the parent and the
	//recv() of a child, so each notices is_interrupted on its main thread
	memset( &sa, 0, sizeof( sa ));
	sa.sa_handler = signal_handler;
	sigaction( SIGINT,  &sa, NULL );
	sigaction( SIGTERM, &sa, NULL );
	sigaction( SIGABRT, &sa, NULL );
}


int main( int argc, char** argv ) {
	uint16_t port_number = 5000; //port on that the program listens
	size_t threads_count = 1;    //number of threads for each process

	int client_socket, pid, i;

	char str_buffer[256];
	const size_t str_buffer_size = 256;

	struct sockaddr_in in_server_addr, in_cli_addr;
	struct sockaddr_un un_server_addr, un_cli_addr;

	char un_domain_name[ MAX_FILENAME_SIZE + 1 ];
	bool is_unix_socket;

	socklen_t socklen;
	size_t size, cores_count = 0, alerts_count = 0;
	uint32_t *core_mask = NULL, *core_mask_ptr;

	mmt_sec_callback _print_output;

	char rule_mask[ MAX_RULE_MASK_SIZE ], excluded_rules_mask[ MAX_RULE_MASK_SIZE ];

	parse_options(argc, argv, &port_number, un_domain_name, &threads_count,
			&cores_count, &core_mask, excluded_rules_mask, rule_mask, &verbose );

	is_unix_socket = (port_number == 0);

	mmt_assert( threads_count == 1 || threads_count <= cores_count, "Core mask is not enough for %zu threads",  threads_count );

	mmt_assert( threads_count > 0 && cores_count % threads_count == 0, "Number of lcores must be multiple of %zu", threads_count );

	mmt_sec_init( excluded_rules_mask );

	proto_atts_count = mmt_sec_get_unique_protocol_attributes( & proto_atts );
	//init mmt-sec to verify the rules

	if( verbose ){
		//TODO: uncomment this after testing
//		mmt_info(" MMT-Security version %s verifies %zu rule(s) using %zu thread(s).",
//						mmt_sec_get_version_info(), rules_count, threads_count );
//		if( is_unix_socket == NO )
//			mmt_info(" It is listening on port %d\n", port_number );
//		else
//			mmt_info(" It is listening on \"%s\"\n", un_domain_name );
	}

	/* create internet socket */
	if( is_unix_socket == NO ){
		socket_server = socket( AF_INET, SOCK_STREAM, 0 );

		if( socket_server < 0) mmt_halt("Error on opening socket");


		/* Initialize socket structure */
		bzero((char *) &in_server_addr, sizeof( in_server_addr ));

		in_server_addr.sin_family      = AF_INET;
		in_server_addr.sin_addr.s_addr = htonl( INADDR_ANY );
		in_server_addr.sin_port        = htons( port_number );

		/* Now bind the host address using bind() call.*/
		mmt_assert( bind(socket_server, (struct sockaddr *) &in_server_addr, sizeof(in_server_addr)) >= 0,
			"Error on binding");
		socklen = sizeof( in_cli_addr );
	}else{
		//create unix socket
		socket_server = socket( AF_UNIX, SOCK_STREAM, 0 );

		if( socket_server < 0) mmt_halt("Error on opening socket");


		/* Initialize socket structure */
		bzero((char *) &un_server_addr, sizeof( un_server_addr ));

		un_server_addr.sun_family = AF_UNIX;
		strcpy( un_server_addr.sun_path, un_domain_name );
		unlink( un_server_addr.sun_path );

		/* Now bind the host address using bind() call.*/
		mmt_assert( bind( socket_server, (struct sockaddr *) &un_server_addr, sizeof( un_server_addr) ) >= 0,
				"Error on binding");
		socklen = sizeof( un_cli_addr );
	}

	/* Now start listening for the clients, here
	 * process will go in sleep mode and will wait
	 * for the incoming connection
	 */
	listen( socket_server, 5 );//limit the number of outstanding connections in the socket's listen queue



	clients_count = 0;
	core_mask_ptr = NULL;

	register_signals();
	//ignore child fate, don't let it become zombie
	signal( SIGCHLD, SIG_IGN );

	//this loop is broken by is_interrupted (Ctrl+c)
	while( ! is_interrupted ) {
			//accept: wait for a connection request
		if( is_unix_socket == NO )
			client_socket = accept( socket_server, (struct sockaddr *) &in_cli_addr, &socklen );
		else //unix socket
			client_socket = accept( socket_server, (struct sockaddr *) &un_cli_addr, &socklen );

		if( client_socket < 0 ){
			if( is_interrupted )
				break;
			mmt_halt("Error on accept");
		}

		if( core_mask )
			core_mask_ptr = &core_mask[ clients_count * threads_count % cores_count ];

		clients_count ++;

		/* Create child process */
		pid = fork();

		if( pid < 0 ){
			mmt_error("Cannot fork a new process");
			close( client_socket );
			continue;
		}
		else if (pid == 0) {
			/*===========================*/
			/* This is the child process */

			// child doesn't need the listener
			close( socket_server );
			socket_server = -1;
			socket_client = client_socket;

			if( verbose ){
				//convert client's IP to readable text
				if( is_unix_socket == NO ){
					inet_ntop(AF_INET, &in_cli_addr.sin_addr.s_addr, str_buffer, str_buffer_size );
					mmt_info( "%3zuth connection is coming from %s:%d ... processed by proc. %d",
							clients_count, str_buffer, in_cli_addr.sin_port, getpid() );
				}else{
					//TODO: uncomment this after testing
//					mmt_info( "%3zuth connection is coming from local ... processed by proc. %d",
//							clients_count, getpid() );
				}
			}

			if( core_mask_ptr != NULL ){
				//main thread on the last core
				if( move_the_current_thread_to_a_processor( core_mask_ptr[ threads_count - 1 ], -15 ) )
					mmt_warn("Cannot set affinity of process %d on lcore %d", gettid(), core_mask_ptr[ threads_count - 1 ] );
			}

			//register signal handler for this child process
			register_signals();

			//do not need output
			if( output_file_string[0] == '\0' &&  output_redis_string[0] == '\0' )
				_print_output = NULL;
			else{
				//init output
				verdict_printer_init( output_file_string, output_redis_string );
				_print_output = mmt_sec_print_verdict;
			}

			//init mmt-sec to verify the rules
			sec_handler = mmt_sec_register( threads_count, core_mask_ptr, rule_mask, verbose, _print_output, NULL );


			//mark the starting moment
			if( verbose )
				gettimeofday( &start_time, NULL );

			//do processing
			size = receiving_reports( client_socket );

			close( client_socket );
			socket_client = -1;

			//finish
			alerts_count = termination();

			if( verbose ){
				gettimeofday( &end_time, NULL );
				mmt_info( "%3zuth connection sent %9zu reports, in %7.2fs, generated %9zu alerts",
						clients_count, size, time_diff( start_time, end_time ), alerts_count
				);
			}

			mmt_mem_free( core_mask );

			verdict_printer_free();

			exit( EXIT_SUCCESS );

			/*End of child process       */
			/*===========================*/
		}
		else {
			/* pid > 0. This is the parent process.
			 * The child process handles the connection,
			 * so we don't need our copy of the connected socket descriptor.
			 * Close it.  Then continue with the loop and accept another connection.
			 */
			close( client_socket );
		}
	}

	if( is_interrupted )
		mmt_error( "Interrupted proc %d - releasing resource ... (press Ctrl+c again to exit immediately)", (int) getpid() );

	termination();

	return EXIT_SUCCESS;
}
