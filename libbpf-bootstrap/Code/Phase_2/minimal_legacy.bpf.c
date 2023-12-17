/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
char * str;
typedef int pid_t;
int my_pid = 0;
int state;
int dead;
//char LICENSE[]dd SEC("license") = "dd";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 10000);
	__type(key, int);
	__type(value, int);
} my_pid_map SEC(".maps");
int cnt = 0;
int fun(int sys_id,int state){


return -1;
}
int countdown = 0;
SEC("raw_tracepoint/sys_enter")
int handle_tp(struct bpf_raw_tracepoint_args *ctx)
{
	int possibleDead = 0;

//////////// Enter Size Of Matrix Here /////////////
int n = 17;
///////////////////////////////////////////////////
	

	 int pid= bpf_get_current_pid_tgid() >> 32;
	 if (my_pid!= pid)
	 	return 0;
	int sys_id = ctx->args[1];
	if(!countdown){

	int ans = 0;
	 for (int i=0;i<n;i++){
	 	int ind = state*n + i;
	 	int * val = (int *)bpf_map_lookup_elem(&my_pid_map, &ind);
	 	if(val){
	 		int fl = 0;
	 		if(*val == sys_id){
	 			state = i;
	 			ans = 1;
	 			break;
	 		}

	 		else if(*val == -1){
	 			if (i == dead) possibleDead = 1;
	 			for(int j = 0;j<n;j++){
	 				int in = i*n+j;
	 				int *valu = (int *)bpf_map_lookup_elem(&my_pid_map, &in);
	 				if(valu){
	 					if(*valu == sys_id){
	 						state = j;
	 						fl = 1;
	 						ans = 1;
	 						break;
	 					}
	 				}
	 			}
	 		}
	 		if(fl) break;

	 	}


	 }

	 if(ans == 0) {
	 	if(possibleDead && sys_id == 3) {
state = dead;
countdown++;
	 }
	 else {
	 		bpf_send_signal(9);
	 }

	 }

}
 
else {
	bpf_send_signal(9);
}

	return 0;
}
