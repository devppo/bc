#include <../common/include/common/log.h>
#include "blocks_thread.h"

bool init_default_db(const char *init_dbname) {
	char Status[MINIMAL_STATUS_LENGTH] = {'\0'};
	const char *dbnm;
	if (!strlen(init_dbname))
		dbnm = DEFAULT_DB;
	else
		dbnm = init_dbname;
	if (!db_singleton.init(dbnm, Status, COUNT(Status))) {
		logger.log(Status);
		public_type pub_key;
		private_type priv_key;
		if (gen_keys_pair(pub_key.data, public_type::get_sz(), priv_key.data, private_type::get_sz(), Status,
						  COUNT(Status))) {
			logger.log(Status);
			if (db_singleton.init(dbnm, pub_key, priv_key, Status, COUNT(Status))) {
				logger.log(Status);
				return true;
			} else {
				logger.err(Status);
			}
		} else {
			logger.err(Status);
		}
		return false;
	} else {
		logger.log(Status);
		return true;
	}
}
