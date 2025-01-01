
- **To Install Docker Engine on Ubuntu**

```bash
sudo apt-get install docker-ce docker-ce-cli containerd.io
```
- Verify that Docker Engine is installed correctly by running the `hello-world` image.

```bash
sudo docker run hello-world
```

- **Post-installation steps for Linux**
- To create the docker group and add your user:

1. Create the docker group.

```bash
sudo groupadd docker
```

2. Add your user to the docker group.

```bash
sudo usermod -aG docker $USER
```

3. To activate the changes to groups.

```bash
newgrp docker 
```

4. Verify that you can run docker commands without sudo.

```bash
docker run hello-world
```

`Note`: If user is not added to the docker group then `sudo` access is required to run the project .

# CVE Scanner

Follow following steps to setup the system.

- Clone the repository.

```bash
git clone ssh://git@stash.alm.mentorg.com:7999/cvec/cve-checker-tool-4.0.git --branch CVE-4.0
```


- Change to the cloned directory.

```bash
cd cve-checker-tool-4.0
```

- Build docker image.

```bash
docker build -t 'cve_4.0_latest' .
```
> - It will take approximately `30 minutes` to build the docker image

- Note : Go to directory where cve-checker-tool-4.0 folder is there 

- Create file `make_container.sh` to make a `docker container`.


```bash
docker run \
 --volume="<PATH TO cve-checker-tool-4.0>:/cve-checker-tool-4.0" \
 --volume="<PATH TO mount for uploads and downloads>:/PATH TO mount for uploads and downloads" \
 --name cve_4.0_development \
 -p 8856:8856 \
 -p 8857:8857 \
 -p 8858:8858 \
 -it <image_id> \
 /bin/bash
```

- Example 


```bash
docker run \
--volume="/scratch/TempCheckout/cve-checker-tool-4.0/:/cve-checker-tool-4.0" \
--volume="/scratch1/folder:/scratch1/folder" \
--name development \
-p 8857:8857 \
-p 8856:8856 \
-p 8868:8858 \
-it 'cve_4.0_latest' \
/bin/bash
```

> - `image_id` can be listed by using `docker images` command.
> - sample of `image-id` - `12e076ef2348`
> - You can choose any `one port` to map.
> - This `make_container.sh` will start the docker container.

- Run make_container.sh

```bash
./make_container.sh
```
- Some useful docker commands.

```bash
docker start <container_name> #To start the container.
docker stop <container_name> #To stop the running container.
docker attach <container_name> #To attach the started container.
```

`NOTE` : You will be on the docker prompt after running make_container.sh

-In order to run your commands inside a running container use:

```bash
docker exec -it <container_id> /bin/bash
```
- To get container id use `docker ps -a` 

# Server


- Go inside Server directory

```bash
cd /cve-checker-tool-4.0/cli/Server
```

Follow following steps to create & update the database.
Have to run it once to just create the database and can be update the databse whenever required by running update_database.py


- **To set the working dir,upload dir and download dir path**
```bash
python3 pathset.py -v1 <path/to >/download_dir -v2 <path/to >/upload_dir -v3 <path/to >/working_dir
```

`NOTE` : All these paths should be inside additional path directory which is mounted during running container
- Example

```bash
python3 pathset.py -v1 /scratch1/folder/download_dir -v2 /scratch1/folder/upload_dir -v3 /scratch1/folder/working_dir

```

- **To create v2.0  Database:**
```bash
Add 'NVDDatabase_v2.0.db' (database name) in 'settings.py' file
Run 'setup_v2.0.sh' (./setup_v2.0.sh)
```


- **To update v2.0  Database:**
```bash
Add 'NVDDatabase_v2.0.db' (database name) in 'settings.py' file
Run 'update_v2.0.sh' (./update_v2.0.sh)
```

# Confiure CRON Job

- Go inside Server  directory and open cron tab

```bash
cd /cve-checker-tool-4.0/cli/Server
crontab -e
* * * * * /usr/bin/python3 /cve-checker-tool-4.0/cli/Server/manage.py runcrons
```

- Add the following line to schedule the cron job to run every 12 hour

```bash
* * * * * /usr/bin/python3 /cve-checker-tool-4.0/cli/Server/manage.py runcrons
```

-Run the cron command to check manually

```bash
/usr/bin/python3 /cve-checker-tool-4.0/cli/Server/manage.py runcrons
```

-Start the cron 

```bash
cd /cve-checker-tool-4.0/cli/Server
sudo service cron start
```




# Client

If you want to run the tool through CLI then follow the steps belows:-

- Go inside Client directory

```bash
cd /cve-checker-tool-4.0/cli/Client
```
- **To set the working dir,upload dir and download dir path**
```bash
python3 pathset.py -v1 <path/to >/download_dir -v2 <path/to >/upload_dir -v3 <path/to >/working_dir
```

`NOTE` : All these paths should be inside additional path directory which is mounted during running container
- Example

```bash
python3 pathset.py -v1 scratch1/folder/download_dir -v2 scratch1/folder/upload_dir -v3 scratch1/folder/working_dir

```



- **To run the Client**

- Go inside Client directory


```bash
cd /cve-checker-tool-4.0/cli/Client
python3 manage.py makemigrations
python3 manage.py migrate
```

Follow following steps to gnerate report based on manifest.


- **To search CVE through manifest:**
```bash

python3 cve_search_manifest.py -m "manifest_file_name in sample_manfest_files"

```
- **To search CVE through package name and version:**
```bash

python3 cve_search_manifest.py -p "package_name" -v "version_number"

```


# PKCT

If you want to run the tool through CLI then follow the steps belows:-

- Go inside Client directory

```bash
cd /cve-checker-tool-4.0/cli/Client
```



- **To run the pkct**

- 


```bash
cd /cve-checker-tool-4.0/cli/Client
python3 manage.py makemigrations
python3 manage.py migrate
```

Follow following steps to gnerate report based on manifest.


- **To check patch verification through manifest:**
```bash

python3 pkct_main.py  -gk "user kernel repo link" -gb "user kernel branch name" -dk "dot kernel folder name" -db "dot kernel stable branch name" -m "manifest_file_name in sample_manfest_files"

```
- **To check patch verification through package name and version:**
```bash

python3 pkct_main.py -gk "user kernel repo link" -gb "user kernel branch name" -dk "dotkernel" -ub master -build "BuildFileName in Client directory" -db "dot kernel stable branch name" -p "package_name" -v "version_number"

```

- **Example**
```bash

python3 pkct_main.py -gk ssh://git@stash.alm.mentorg.com:7999/socsamexv9/automotive_ahh3_v9_kernel.git -gb mentor/cl45_FC-231026 -dk dotkernel_stable -ub master -build BuildFile-CL45.txt -db v5.15.165 -p kernel -v 5.15.74

```


# HMI

Running the tool through HMI or user interfaces:-


- Edit the `settings.py` file

```bash
cd /cve-checker-tool-4.0/hmi/CVEHMI/CVEHMI
vi settings.py
Add your 'IP' in the allowed host
Add frontend 'BASE_URL'(URL on which frontend is deployed including the port number.) in the cors allowed host
```
- To get your IP address use hostname -I


- To create Database

```bash
1. cd /cve-checker-tool-4.0/hmi/CVEHMI
2. python3 manage.py makemigrations
3. python3 manage.py migrate
```


- To create `media` directory
```bash
1- cd /cve-checker-tool-4.0/hmi/CVEHMI/hmiapp
2- mkdir media
```


- To run the Server

```bash
python3 manage.py runserver 0.0.0.0:port_number (Use 8856 or 8857 as port_number)
```