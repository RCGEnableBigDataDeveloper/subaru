I created 3 tables in a new database named EDW...

1. w_vehicle_d (from oracle)
2. w_vehicle_hist_d (from csv)
3. w_model_d (from oracle)

all tables seem to have correct counts...

hive> select count(*) from edw.w_vehicle_d ;
2079398

hive> select count(*) from edw.w_vehicle_hist_d ;
32701090

hive> select count(*) from edw.w_model_d ;
3807

The VIN is masked in w_vehicle_d  and w_vehicle_hist_d 

hive> select vin  from edw.w_vehicle_d limit 5;
oBwcxYW2aUu64CRnzKwXcw==
G8LbtiGCo0i64CRnzKwXcw==
FxSHRA8TLfK64CRnzKwXcw==
qLO0MQ5JcE+64CRnzKwXcw==
NX7+Jjyb01K64CRnzKwXcw==

The VIN can be viewed using the unmask UDF

# export HIVE_AUX_JARS_PATH=/home/soaadmin
# hive
hive> add jar /home/soaadmin/mask.jar
hive> CREATE FUNCTION mask AS 'com.subaru.udf.Mask';
hive> CREATE FUNCTION unmask AS 'com.subaru.udf.UnMask';
hive> select unmask(vin) from edw.w_vehicle_d limit 5;
GH486357
GH486506
GH486600
GH486606
GH487031


select unmask(integration_id) from edw.w_vehicle_d limit 5;


impala-shell -i impala-4ypvrnunjohqxubz.pvt.su150.cazena.com -d default -k --ssl --ca_cert=/etc/pki/tls/certs/ca-bundle.crt 