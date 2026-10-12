SERVICE=fritz_log_read.service

status start stop restart:
	systemctl --user $@ $(SERVICE) 

launch:
	python fritz_log_read2.py
