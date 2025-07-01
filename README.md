### Описание

Бесплатный Clamav, Kaspersky Anti-Virus (AVP), Sophos Anti-Virus, Trend Micro, Dr.Web и SpamAssassin внешний фильтр 
(плагин) для почтового сервера CommuniGate Pro.

Используется для сканирования всех сообщений, которые проходят через почтовый сервер CommuniGate Pro www.stalker.com

Clamav - бесплатный антивирус: www.clamav.net  
Касперский антивирус: www.avp.ru  
Sophos Anti-Virus: www.sophos.com Демон Sophie для Sophos www.vanja.com  
Trend Micro Anti-Virus: www.antivirus.com Демон Trophie для Trend Micro www.vanja.com  
Dr.Web www.drweb.ru  
SpamAssassin Anti-Spam: www.spamassassin.org  

Основной сайт для cgpav: program.farit.ru  
Первые версии cgpav были созданы и поддерживаются Дамиром Бикмухаметовым: ftp://bfm.bashnet.ru/CGPAV

### Как программа работает

Программа читает запросы со своего стандартного ввода в форме:  
`seqNum FILE fileName`  
например:  
`1111 FILE 111111.msg`

После этого она разбирает эту строку на части и добавляет новый элемент в список-структуру, содержащий _seqnum_ и 
_filename_. Программа создает дочерний процесс для каждого элемента из списка, который посылает запрос, включающий 
полное имя файла, составленное из cgpro_home + / + filename, антивирусному демону и ждет результатов сканирования.  
Количество дочерних процессов зависит от количества Enqueuer processors в настройках CommuniGate Pro settings и значения 
_max_childs_ в конфигурационном файле cgpav.conf. Желательно, чтобы они были равны и больше единицы. 5 - нормальное 
значение.

В зависимости от результата сканирования программа посылает CommuniGate Pro различные строки ответа.

Когда сообщение чистое:  
`seqNum OK`  
Также она отвечает OK во всех "сложных" ситуациях: таймаут при сканировании, анти-вирусный демон не отвечает и т.д.

Когда сообщение заражено вирусом, программа печатает что-то типа:  
`seqNum ERROR "WARNING! Your message is infected by VIRUS: I-Worm.Sircam.c"`  
Когде сообщение распознано как спам, то программа выдает:  
`seqNum ERROR "You are a known spammer.\\nYour message was rejected"`  
Когда CommuniGate Pro получает такой ответ, то создает сообщение о недоставке, включающее этот текст.

Она также может просто тихо удалять сообщения без доставки, выдав заголовок **DISCARD** или добавлять специальные 
заголовки с помощью команды **ADDHEADER** - когда обнаружены вирус или спам, позволяя конечному пользователю фильтровать 
такие сообщения в своей собственной почтовой программе. Конечно, нормальные пользователи не захотят получать вирусы, так 
что infected_action будет reject или discard, а вот в спам программа может записать и "хорошие" сообщения, так что лучше 
оставить окончательное решение самому пользователю, spam_action как addheader. Однако, могут быть проблемы с некоторыми 
глупыми почтовыми клиентами типа Microsoft Outlook Express, который вроде не умеет фильтровать по заголовкам. В таком 
случае пользователь может просто создать правило, чтобы все помеченные вышеупомянутым заголовком складывались в 
определенную папку. Её можно будет посмотреть с помощью IMAP или через почтовый web-интерфейс.

Также программа может посылать дополнительные сообщения с уведомлениями как отправителю зараженного письма, так и 
получателям, записывая их в директорию Submitted CommuniGate Pro. Модуль PIPE CommuniGate Pro периодически сканирует 
эту директорию и отправляет все все сообщения из нее.
Вы можете включить текст на разных языках (в том числе на русском) в уведомления, пометив эти языки в конфигурационном 
файле.
Также программа может отсылать уведомления на адрес постмастера всего почтового сервера и постмастерам виртуальных 
доменов.

Если программа обнаружила вирус, то она записывает имя вируса, e-mailы отправителя и получателей в лог-файл.

Когда в программе происходят временные ошибки, то она отвечает вроде этого:  
`seqNum REJECTED "Antiviral filter unavailable. Will try later"`  
Такая ситуация может произойти, например, если скрипт для обновления вирусных баз передернул антивирусный демон.  
Само сообщение не отвергается, оно остается в очереди CommuniGate Pro для дальнейшего сканирования.

Если количество последовательных REJECTED превышает значение _max_errors_, заданное в конфигурационном файле, то 
программа начинает отвечать ОК, пока не возобновится нормальное функционирование антивирусного демона.

Для сканирования сообщений на спам используется стандартный демон spamd из дистрибутива SpamAssassin. 
По умолчанию добавляется заголовок X-Spam-Status в сообщение при превышении очков, заданных _required_hits_, 
позволяя его потом отфильтровать в клиентском почтовом клиенте или с помощью правила в CommuniGate Pro переправить 
его в отдельную папку.

Кроме того можно определить действие при достижении _extra_spam_score_, например, тихо удалять сообщение(discard). 
Обычно его устанавливают достаточно большим, чтобы отсекался явный спам, не засоряя сервер. Это полезно, т.к. 
ольшинство пользователей никак не используют вышеупомянутый заголовок.

Пример web-интерфейса на php для изменения настроек антиспамового фильтра прилагается. Пользователи могут менять спам 
хиты, выбирать различные действия, отключать некоторые тесты. Также они могут создавать правило для сохранения спам в 
специальную папку одним кликом мышки.

### Установка

Распакуйте исходники:  
`gzip -cd cgpavXXX.tar.gz | tar xvv-`

Запустите ./configure

Вы можете изменить параметры, используя опции:  
--with-antivirus=av_name Имя антивирусного демона: [avp OR sophos OR clamav OR trophie OR drweb OR no]  
--with-spamassassin=yes/no Использовать SpamAssassin или нет  
Профили пользователей для SpamAssassin могут храниться в базе:  
--with-mysql=yes/DIR MySQL, укажите корневую директорию  
--with-pgsql=yes/DIR PostgreSQL, укажите корневую директорию  
Программа будет пытаться найти headerы и libы сама.  
--with-cgpro-home=PATH путь к корневой директории CommuniGate Pro [/var/CommuniGate]  
--with-cgpro-settings=PATH путь к директории Settings CommuniGate Pro [cgpro-home/Settings]  
--with-cgpro-submitted=PATH путь к директории Submitted CommuniGate Pro [cgpro-home/Submitted]  
Например:  
`./configure --with-antivirus=clamav --with-cgpro_dir=/var/CommuniGate`

Вы можете опустить эти опции, программа выведет меню для выбора и попытается определить директории сама.

Затем:  
```
make
make install
```

Исполняемый файл cgpav будет скопирован в корневую директорию _cgpro_dir_, упомянутую выше, и конфигурационный файл 
cgpav.conf - в директорию Settings внутри этой корневой директории.

Конечно, вы можете не делать make install, а скопировать эти файлы куда-нибудь в другое место самостоятельно.

### Установка антивирусного демона и SpamAssassin

Скачайте тестовый вирус с сайта www.eicar.org

Запустите Install в дистрибутивах kavdaemon или sophos, следуйте инструкциям.

#### CLAMAV:

Некоторые дистрибутивы Linux (.deb и .rpm пакеты) и другие Unix уже содержат clamav. Но его всегда можно скачать с 
clamav.sourceforge.net, затем запустить `./configure, make, make install`.
Отредактируйте clamav.conf, мы будем использовать только Local Socket. Проверьте, что значение LocalSocket соответствует 
значению clamd_socket в cgpav.conf.
Также clamav должен запускаться под пользователем root или другим пользователем в группе 'mail', чтобы иметь доступ к 
директориям CommuniGate Pro:  
`User root`  
Запустите демон clamd и проверьте с помощью clamdscan тестовый вирус.

##### КАСПЕРСКИЙ (kavdaemon):

Добавьте путь к директории Queue Communigate Pro в параметры стартового файла kavdaemon (/etc/init.d/kavdaemon):  
`DPARMS="-I0 -Y /var/CommuniGate/Queue"`  
Это позволит AVP сканировать данную директорию на вирусы.

Или просто добавьте этот путь в AvpUnix.ini или defUnix.prf [Object]->Names со значком звездочки впереди:  
`Names=*/home;*/var/CommuniGate/Queue`  
(Не забудьте про звездочку *, чтобы активизировать этот путь).

Запустите kavscanner, чтобы он нашел тестовый вирус.

##### SOPHOS:

Создайте группу sweep и пользователя sweep.

Инсталлятор может не найти некоторые переменные окружения вроде MANPATH, установите их:
```
MANPATH="$MANPATH:/usr/local/man"
export MANPATH
```

Создайте симлинк:  
`ln -s /usr/local/lib/libsavi.so.2 /usr/local/lib/libsavi.so`

Запустите sweep, чтобы он нашел тестовый вирус.

Скачайте и установите демон sophie. Согласно инструкциям на время написания, запустите ./configure, скопируйте 
sophie.cfg и sophie.savi в /etc и отредактируйте их. sophie.savi.individual - неплохая основа для sophie.savi
Нужно сменить user и group в sophie.cfg на root или на пользователя, под которым работает CommuniGate Pro.

Вы можете скомпилить программу scan_file.c в sample_appls/sock, чтобы протестировать демон.

#### TREND MICRO:

Положите libvsapi.so и файл с паттернами вирусов в директорию /etc/iscan. Триальные версии можно скачать с 
www.antivirus.org  
Скачайте демон Trophie www.vanja.com  
`./configure --with-user=root --with-group=root`

#### DR.WEB:

Установите имя сокета в /etc/drweb/drweb32.ini:  
`/var/run/drwebd.socket`  
Пользователь 'drweb' должен быть в группе 'mail', чтобы иметь возможность доступа в директорию /var/CommuniGate/Queue. 
Или запускайте drwebd под 'root' в drweb32.ini:  
User = root  
Проверьте функционировани drwebd с помощью программы drwebdc.

#### SPAMASSASSIN:

Скачайте SpamAssassin отсюда: www.spamassassin.org.

Скомпилируйте:
```
perl Makefile.PL
make
make test
make install
```
Или скачайте rpm или deb пакеты для вашего дистрибутива.

Протестируйте работоспособность:
```
spamassassin -t < sample-spam.txt > /tmp/sample-spam.txt
spamassassin -t < sample-nonspam.txt > /tmp/sample-nonspam.txt
```

Проверьте, что /tmp/sample-spam.txt помечен как спам.

### Конфигурирование

Конфигурационный файл cgpav.conf должен располагаться в директориях /var/CommuniGate/Settings, /var/CommuniGate или /etc.  
Про запуске программа просматривает сначала директорию /var/CommuniGate/Settings, потом /var/CommuniGate и /etc, она 
будет использовать первый найденный cgpav.conf. Вы можете изменить это, отредактировав cfg.c или добавив опцию -f при 
запуске cgpav:  
`./cgpav -f /var/elsewhere/cgpav.conf`

Если программа не сможет найти cgpav.conf, или если вы закоментируете какой-нибудь обязательный параметр в нем, то 
программа будет использовать значения по умолчанию из cfg.h

Большинство значений из cgpav.conf являются достаточными для установок cgpro и антивирусов по умолчанию. Нужно будет 
установить пароль для доступа к базе данных, если вы будете пользоваться профилями в базе.

Чтобы включить русский язык в уведомлениях, пометьте
```
charset = koi8-r
russian = true
```

Некоторые опции могут располагаться на нескольких строках, обычно это перечисления через запятую. Чтобы продлить её на 
следующую строку, введите имя параметра в начале строки. Используйте столько строк, сколько нужно.

Полезным может оказаться внесение сеток, с которых отправляют почту ваши пользователи, в local_networks. Тогда вся 
почта, приходящая с них, не будет проверяться на спам, значительно уменьшая нагрузку на сервер. Только не забудьте 
исключить из них все адреса релеев, откуда может пересылаться входящая почта.

### Тестирование

Вы можете получить больше отладочной информации, если сконфигурируете cgpav в режиме DEBUG:  
`CFLAGS="-g -DDEBUG" ./configure`  
В этом режиме cgpav работает в однопроцессном режиме.  
Не забудьте потом переконфигурировать его обратно:  
`./configure`

Скопируйте тестовый вирус (например, eicar.com) в директорию /var/CommuniGate

Запустите фильтр из командной строки ./cgpav  
Потом введите:  
`1 FILE eicar.com`

Если вы видите что-то типа  
`1 ERROR "WARNING! Your message was infected by VIRUS: EICAR-AV-Test"`  
то cgpav работает нормально.

Если вы видите только лишь  
`1 OK`  
то программа не находит вирусов.

Касперский антивирус:  
Сначала посмотрите в лог файл kavdaemon (/root/kavscan.rpt). Если вы видите, что kavdaemon обнаружил вирус, то вы можете 
раскомментировать строку с ответом демона в функции avp_scan_file в файле avpcomm.c.  
В Linux ответ: 0x134 (octal) для инфицированных и 0x130 для чистых. В Sparc Solaris: 0x1340000 и 0x1300000

### Установка в CommuniGate Pro

Прочитайте документацию с их сайта: www.stalker.com

SETTINGS->Rules  
Priority Name  
10 virus scan  

Нажмите на Edit  
Data  
Message Size greater than 1024  

Action  
ExternalFilter  

Перейдите в Settings->General->Helpers  
и в меню Content Filtering добавьте путь к программе  

Пометьте Content Filtering  
Program Path: cgpav  
если cgpav расположена в корневой директории CommuniGate Pro или введите абсолютный путь.

Оставьте параметры "Time-out" и "Auto-Restart в состоянии disabled.  
Изменяйте их только если cgpav падает. Вообще-то, cgpav сделан так, что основной процесс сканирования происходит в 
дочерних процессах, и их падение не должно вызывать падения основного процесса.

### Конфигурирование SpamAssassin

Проверки SpamAssassin по умолчанию выключены. Вы должны быть очень осторожны, потому что он может отвергать некоторые 
полезные сообщения. Это не пятиминутное дело!

После установки SpamAssassin вы должны запустить какую-нибудь быструю базу данных. MySQL www.mysql.com - наилучший 
выбор, кроме того поддерживается PostgreSQL. Нужно будет установить libmysqlclient-dev или postgresql-dev пакеты, а 
также Perl DBI и DBD модули. Далее рассматривается использование MySQL, вы должны настроить конфигурацию для другой 
базы данных соответствующим образом.

В базе мы будем хранить собственные настройки для каждого пользователя.  
Зайдите в mysql как root:  
`mysql -u root -p`  
и создайте новую базу, например, под названием spamassassin:  
`mysql>CREATE DATABASE spamassassin;`  
После этого создайте пользователя и дайте ему привилегии, например, spamassassin:  
`mysql>GRANT ALL ON spamassassin.* TO spamassassin@localhost IDENTIFIED BY 'secretpassword';`  
Конечно, вместо secretpassword введите какой-нибудь пароль.  
Отсоединитесь от базы.

Создайте в базе таблицу userpref:
```sql
CREATE TABLE userpref (
username varchar(100) NOT NULL,
preference varchar(30) NOT NULL,
value varchar(100) NOT NULL,
prefid int(11) NOT NULL auto_increment,
PRIMARY KEY (prefid),
INDEX (username)
) TYPE=MyISAM;
```

Вы можете найти файл userpref.sql в директории spam/sql.  
Запустите из командной строки:  
`mysql -u spamassassin -p spamassassin < userpref.sql`

Скачайте и установите Perl модули DBI и DBD для вашей базы данных search.cpan.org. Или установите их из готовых пакетов 
или rpm.

Перейдите в конфигурационную директорию SpamAssassin: /etc/mail/spamassassin или /etc/spamassassin. Добавьте в local.cf 
следующие строки:  
```
user_scores_dsn	DBI:mysql:spamassassin:localhost  
user_scores_sql_username	spamassassin  
user_scores_sql_password	secretpassword
```  
Параметр user_scores_dsn должен быть в такой форме:  
`user_scores_dsn DBI:driver:database:hostname[:port]`  
Измените его соответственно для своей базы данных.

Если вы будете использовать spamd на том же компьютере, то соединение лучше проводить через unix сокет, если на 
удалённом, то придётся использовать tcp сокет. Установите соответствующее значение в cgpav.conf:  
`spamassassin_socket_type = unix`  
Если вы используете unix сокет, то в опциях запуска spamd поставьте примерно следующее:  
`-d -m 10 -x -q -u mail --socketpath=/var/run/spam`  
Если же tcp сокет, то:  
`-d -m 10 -x -q -u mail -i spamd.server.ip -p 783 -A your.mail.server.ip`  
Где spamd.server.ip - IP-адрес компьютера, на котором слушает spamd, your.mail.server.ip - IP-адрес вашего почтового 
сервера, с которого он соединяется со spamd сервером. Можно через запятую поставить несколько IP.

Проверьте функционирование spamd с помощью программы spamc:  
`spamc -U /var/run/spam < sample-spam.txt > sample-spam.log`  
Вы можете добавить в опции spamd ключик -D (debug), и сможете найти более детальную информация в логах.

Создайте файл 50_whitelist.cf в конфигурационной директории SpamAssassin и добавьте домены своих соседей провайдеров, 
чтобы иметь с ними меньше проблем:  
`whitelist_from *@goodprovider.ru`

Распечатайте файл с очками по умолчанию всех правил SpamAssassin, ищите их здесь: www.spamassassin.org  
Вы можете настраивать эти очки по своему вкусу или даже выключить некоторые, добавив их с 0 в local.cf или любой *.cf 
файл в конфигурационной директории SpamAssassin. Например:  
```
# Undisclosed-recipients  
score UNDISC_RECIPS 5.0  
```
Вы также можете создать файл 50_blacklist.cf для добавления известных спаммерских доменов:  
`blacklist_from *@flowgo.com`  
Вы можете найти хороший blacklist здесь: www.stearns.org/sa-blacklist/

Также вы можете создать свои собственные правила, используя регулярные выражения. Замечание: очки могут быть и 
отрицательными. Файл 25_head_tests_ru.cf:  
```
header RU_WIN_CHARSET	ALL =~ /windows-1251/i  
describe RU_WIN_CHARSET	ALL: Windows-1251 charset  
score RU_WIN_CHARSET	0.5  
Файл 25_body_tests_ru.cf:  
body RU_ONE_TIME_ACTION	/разовая[\s]+[акция|рассылка]/i  
describe RU_ONE_TIME_ACTION	One time action  
score RU_ONE_TIME_ACTION	1.8  
```
Чтобы реализовать регистронезависимые регулярные выражения (ключик i), вы должны вставить в модули SpamAssassin 
EvalTests.pm и PerMsgStatus.pm установку локали KOI8-R (обычно перед первым use):  
```
use locale;  
use POSIX 'locale_h';  
setlocale(LC_ALL, "ru_RU.KOI8-R");
```  
Вы должны будете патчить их при переустановке SpamAssassin.

Установите web-интерфейс для того, чтобы пользователи могли сами настраивать required_hits, черный и белый списки. 
Пример для php доступен в директории spam/www/php. В этом примере происходит авторизация через 106 порт CommuniGate Pro. 
Вы можете использовать любое другое средство, или интерфейс к базе данных.  
Замечание: вы должны всегда вставлять полный e-mail адрес пользователя в поле username, а не его имя. ivan@domain.ru - 
правильно, ivan - неправильно.

### Известные проблемы

Если вы включаете-выключаете антивирус в Content Filtering в CommuniGate Pro Settings->Helper, старый процесс cgpav 
может оставаться zombie.

Вы можете перегрузить CommuniGate, чтобы убить их.

### Лицензия

Лицензия свободная - GPL.

Однако вы должны приобрести собственную лицензию для Kaspersky Anti-Virus или Sophos Anti-Virus.

Если вы используете демон от Касперского, фильтр не будет работать без ключевого файла. Вы можете заполнить анкету и 
получить триальный ключик, связавшись с ними.  
Sophos антивирус можно скачать с их сайта.

### Советы по Касперскому

Снова, добавьте путь к директории Queue CommuniGate в стартовый скрипт (/etc/init.d/kavdaemon) и в скрипт для обновлений 
(/opt/AVP/kavupdater.sh):  
`DPARMS="-I0 -Y /var/CommuniGate/Queue"`  
Или просто добавьте путь в AvpUnix.ini [Object]->Names с звездочкой * впереди.

Добавьте строку UpdatePath в AvpUnix.ini для скачивания вирусных обновлений (может запускаться по cron):  
`UpdatePath=ftp://ftp.kaspersky.ru/updates/`  
Или используйте другой ftp сервер из файла Updates.lst.

Не расходуйте зазря ресурсы, меняя -I0 (только сканирование на вирусы) на -I2 (лечение вирусов). Файлы в сообщениях 
запакованы MIME и антивирус не сможет вылечить их. Также CommuniGate не любит, когда кто-то изменяет размер посланных 
сообщений.

Измените следующие установки в defUnix.prf:

```
[Options]  
ParallelScan=Yes

[Report]  
Report=No
```

Включайте лог только на стадии тестирования.

### Советы по Sophos

Я включил скрипт для обновления вирусных баз sophosupdate.pl в демон sophie. Возможно, вам придется скачать 
отсутствующие Perl модули, чтобы запустить его, вероятнее всего, Archive::Zip. Поищите их на сайте вашего дистрибутива 
или на search.cpan.org

### Советы по SpamAssassin

В директории cron вы можете найти программу delete_old_mail, с помощью которой можно автоматически удалять сообщения 
больше какого-то периода из папки Spam, куда складываются спамовые сообщения. Модуль CLI.pm для неё находится здесь: 
www.stalker.com/CGPerl

Если вы используете Bayes фильтр в SpamAssassin, внимательно проверьте следующие опции в его настройках:  
```
bayes_path  
bayes_journal_max_size  
bayes_expiry_max_db_size  
bayes_auto_learn_threshold_spam  
```
Будьте внимательны к тем тестам, которые могут реагировать на русские буквы как на "плохие" символы.  
Поставьте:  
```
ok_locales ru  
score SUBJ_ILLEGAL_CHARS 0  
score FROM_ILLEGAL_CHARS 0  
```
Названия тестов, вызвавших срабатывание, пишется в почтовом заголовке X-Spam-Status. Анализируйте их, протестировав 
ообщение с помощью команды  
spamassassin -t < test_message > test_message.log

Если какой-то из тестов работает неправильно, отключите его или дайте маленький score.

### Как проверять сообщения для других серверов

Например, у вас есть сервер mail.domain.ru с установленным антивирусным фильтром и вы хотите защитить другой почтовый 
сервер alpha.domain.ru.

В Settings->Router добавьте строку  
Relay: alpha.domain.ru = alpha.domain.ru@alpha.domain.ru.25.smtp

В DNS записи добавьте MX строки:
```
alpha	IN	MX	10	mail.domain.ru.  
 	IN	MX	20	alpha.domain.ru.
```
### Логи

Программа сохраняет информацию о найденных вирусах, используя стандартный syslog через local0 facility.  
Вы можете заметить строчки типа в syslog:  
Jan 1 00:00:11 mail cgpav: Virus: I-Worm.BadtransII From: anna@mail.host.ru To: antivirus@bashnet.ru

Вы можете изменить log_facility в cgpav.conf, чтобы использовать другой facility (mail, local0 - local7)

Если вы хотите перенаправить сообщения о вирусах в другой файл, отредактируйте файл /etc/syslog.conf  
`local0.* -/var/log/virus.log`

### Авторы

Программирование: Damir Bikmukhametov и Farit Nabiullin.  
Solaris патч для AVP: Vitaly с afn.ru  
Sophie демон: Vanja Hrustic www.vanja.com  
UUdeview библиотека: Frank Pilhofer www.fpx.de SpamAssassin: Jastin Mason www.spamassassin.org  
spamd: Craig R Hughes
