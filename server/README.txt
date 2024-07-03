Şu komutu yalnızca bir kere çalıştırın:

sudo ./remote_conn_set.sh

Yukarıdaki kod, veritabanının kurulduğu sunucunun uzaktan erişime açılmasını sağlamaktadır. Bu nedenle bu kodu sunucuda bir kez çalıştırmanız yeterlidir.

Sunucu ile ilgili kalp atışı, register vb. işlemleri gerçekleştirmek için sunucu açıkken database_run python dosyasını sürekli çalıştırıyor olun:

python3 database_run.py
