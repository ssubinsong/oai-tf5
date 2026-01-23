#ifndef NR_SOFTMODEM_H
#define NR_SOFTMODEM_H

#include <executables/nr-softmodem-common.h>

#include "PHY/defs_gNB.h"

#define DEFAULT_DLF 2680000000

/***************************************************************************************************************************************/
/* TESLA key management defaults                                                                                                        */
/***************************************************************************************************************************************/
#ifdef TF5_ENABLE_TESLA
#define CONFIG_HLP_TESLA_PRIVKEY  "TESLA BLS secret key file (raw binary, 32 bytes)\n"
#define CONFIG_HLP_TESLA_PUBKEY   "TESLA BLS public key file (raw binary, 96 bytes)\n"
#define CONFIG_HLP_TESLA_CHAINLEN "TESLA key chain length (default: 65536, approx. 21.8 minutes with 20ms T_int)\n"
#define TF5_DEFAULT_PRIVKEY_PATH  "./tesla_keys/gnb_tesla_privkey.bin"
#define TF5_DEFAULT_PUBKEY_PATH   "./tesla_keys/gnb_tesla_pubkey.bin"
#define TF5_DEFAULT_CHAIN_LEN     65536
#endif

/***************************************************************************************************************************************/
/* command line options definitions, CMDLINE_XXXX_DESC macros are used to initialize paramdef_t arrays which are then used as argument
   when calling config_get or config_getlist functions                                                                                 */

/*----------------------------------------------------------------------------------------------------------------------------------------------------------------------*/
/*                                            command line parameters common to eNodeB and UE                                                                           */
/*   optname                helpstr                 paramflags        XXXptr                              defXXXval                   type         numelt               */
/*----------------------------------------------------------------------------------------------------------------------------------------------------------------------*/
// clang-format off
#ifdef TF5_ENABLE_TESLA
#define CMDLINE_TESLA_PARAMS_GNB \
  {"tesla-privkey",         CONFIG_HLP_TESLA_PRIVKEY,  0,                .strptr=&tesla_privkey_file,         .defstrval=TF5_DEFAULT_PRIVKEY_PATH, TYPE_STRING, 0},     \
  {"tesla-pubkey",          CONFIG_HLP_TESLA_PUBKEY,   0,                .strptr=&tesla_pubkey_file,          .defstrval=TF5_DEFAULT_PUBKEY_PATH,  TYPE_STRING, 0},     \
  {"tesla-chain-len",       CONFIG_HLP_TESLA_CHAINLEN, 0,                .uptr=&tesla_chain_len,              .defuintval=TF5_DEFAULT_CHAIN_LEN,   TYPE_UINT,   0},
#else
#define CMDLINE_TESLA_PARAMS_GNB
#endif

#define CMDLINE_PARAMS_DESC_GNB { \
  {"m" ,                    CONFIG_HLP_DLMCS_PHYTEST,  0,                .uptr=&target_dl_mcs,                .defintval=0,                     TYPE_UINT,   0},        \
  {"l" ,                    CONFIG_HLP_DLNL_PHYTEST,   0,                .uptr=&target_dl_Nl,                 .defintval=0,                     TYPE_UINT,   0},        \
  {"L" ,                    CONFIG_HLP_ULNL_PHYTEST,   0,                .uptr=&target_ul_Nl,                 .defintval=0,                     TYPE_UINT,   0},        \
  {"t" ,                    CONFIG_HLP_ULMCS_PHYTEST,  0,                .uptr=&target_ul_mcs,                .defintval=0,                     TYPE_UINT,   0},        \
  {"M" ,                    CONFIG_HLP_DLBW_PHYTEST,   0,                .uptr=&target_dl_bw,                 .defintval=0,                     TYPE_UINT,   0},        \
  {"T" ,                    CONFIG_HLP_ULBW_PHYTEST,   0,                .uptr=&target_ul_bw,                 .defintval=0,                     TYPE_UINT,   0},        \
  {"D" ,                    CONFIG_HLP_DLBM_PHYTEST,   0,                .u64ptr=&dlsch_slot_bitmap,          .defintval=0,                     TYPE_UINT64, 0},        \
  {"U" ,                    CONFIG_HLP_ULBM_PHYTEST,   0,                .u64ptr=&ulsch_slot_bitmap,          .defintval=0,                     TYPE_UINT64, 0},        \
  {"usrp-tx-thread-config", CONFIG_HLP_USRP_THREAD,    0,                .iptr=&usrp_tx_thread,               .defstrval=0,                     TYPE_INT,    0},        \
  {"uecap_file",            CONFIG_HLP_UECAP_FILE,     0,                .strptr=&uecap_file,                 .defstrval="./uecap_ports1.xml",  TYPE_STRING, 0},        \
  CMDLINE_TESLA_PARAMS_GNB \
}
// clang-format on

extern uint32_t target_dl_mcs;
extern uint32_t target_dl_Nl;
extern uint32_t target_ul_Nl;
extern uint32_t target_ul_mcs;
extern uint32_t target_dl_bw;
extern uint32_t target_ul_bw;
extern uint64_t dlsch_slot_bitmap;
extern uint64_t ulsch_slot_bitmap;
extern char *uecap_file;
#ifdef TF5_ENABLE_TESLA
extern char *tesla_privkey_file;
extern char *tesla_pubkey_file;
extern unsigned int tesla_chain_len;
#endif

// In nr-gnb.c
extern void init_gNB();
extern void stop_gNB(int);

// In nr-ru.c
extern void init_NR_RU(configmodule_interface_t *cfg, char *);
extern void init_RU_proc(RU_t *ru);
extern void start_NR_RU(void);
extern void stop_RU(int nb_ru);
extern void kill_NR_RU_proc(int inst);
extern void set_function_spec_param(RU_t *ru);

void init_eNB_afterRU(void);

void init_pdcp(void);

#endif
