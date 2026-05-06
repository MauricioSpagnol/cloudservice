#!/usr/bin/env bash
LC_ALL="en_US.UTF-8"
LC_NUMERIC="en_US.UTF-8"
LANG="en_US.UTF-8"
LANGUAGE="en_US:en"
SSD=0
HDD=0
SCORE=0
RED='\033[1;31m'
GREEN='\033[1;32m'
NC='\033[0m'
CYAN='\033[1;36m'

command_exists() { command -v "$@" > /dev/null 2>&1; }

Bps_to_MiBps() { awk '{ printf "%.2f\n", $0 / 1024 / 1024 } END { if (NR == 0) { print "error" } }'; }

finish() { printf '\n'; rm -f test_$$; exit; }
trap finish EXIT INT TERM

dd_benchmark() {
  cd $HOME && LC_ALL=C timeout 25s dd if=/dev/zero of=$1/test_$$ bs=64k count=16k conv=fdatasync 2>&1 | \
    awk -F, '{ io=$NF } END {
      if (io ~ /TB\/s/) {printf("%.0f\n", 1000*1000*1000*1000*io)}
      else if (io ~ /GB\/s/) {printf("%.0f\n", 1000*1000*1000*io)}
      else if (io ~ /MB\/s/) {printf("%.0f\n", 1000*1000*io)}
      else if (io ~ /KB\/s/) {printf("%.0f\n", 1000*io)}
      else { printf("%.0f", 1*io)} }'
  rm -f $1/test_*
}

if ! command_exists dd; then
  printf '%s\n' 'This script requires dd, but it could not be found.' 1>&2
  exit 1
fi

if [[ "$(sysbench --version)" == "" ]]; then
  curl -s https://packagecloud.io/install/repositories/akopytov/sysbench/script.deb.sh | \
    sed 's/dist=${dist}/dist=focal/g' | sudo bash > /dev/null 2>&1
  sudo apt -y install sysbench > /dev/null 2>&1
  if [[ "$(sysbench --version)" == "" ]]; then
    echo -e ""
    echo -e "-------------------------------------------"
    echo -e "| HARDWARE BENCHMARK"
    echo -e "-------------------------------------------"
    echo -e "| Benchmark: FAILED"
    echo -e "| Error: Sysbench installation failed..."
    echo -e "-------------------------------------------"
    echo -e ""
    exit
  fi
fi

vcore=$(getconf _NPROCESSORS_ONLN)
ram=$(LC_ALL=C free -b 2>/dev/null | awk 'NR==2 {print $2}' | \
  grep -Eo '[0-9]+' | printf "%.0f\n" $(awk '{ print $1/1024/1024/1024 }') 2>/dev/null)
core=$(awk -F: '/cpu cores/ {name=$2} END {print name}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//')
if [[ "$core" == "" ]]; then core=$(grep 'processor' /proc/cpuinfo | wc -l); fi

echo -e ""
echo -e "-------------------------"
echo -e "| MEMORY BENCHMARK"
echo -e "-------------------------"
echo -e "| RAM: ${CYAN}${ram}${NC}"
echo -e "-------------------------"
echo -e "| CPU BENCHMARK"
echo -e "-------------------------"

if [[ "$(dpkg --print-architecture)" = *"Jetson"* ]]; then
  cumulus_ram=3
else
  cumulus_ram=7
fi

status=""
if [[ "$ram" -ge "$cumulus_ram" ]] && [[ "$vcore" -ge 4 ]]; then status="CUMULUS"; fi
if [[ "$ram" -ge 30 ]] && [[ "$vcore" -ge 8 ]];              then status="NIMBUS";  fi
if [[ "$ram" -ge 61 ]] && [[ "$vcore" -ge 16 ]];             then status="STRATUS"; fi
if [[ "$status" == "" ]]; then status="FAILED"; fi

echo -e "| CPU vcores: ${CYAN}${vcore}${NC}"

outputdiskbench="Disks Bench:"
loop_mount=$(cd $HOME && LC_ALL=C lsblk -l -b -n | grep 'loop' | \
  awk '{ if ($7 == "/") printf("%.2f\n", $4/(1024*1024*1024))}')

if [[ "$loop_mount" != "" ]]; then
  mount_path="/"
  io1=$(dd_benchmark "$mount_path")
  io2=$(dd_benchmark "$mount_path")
  io3=$(dd_benchmark "$mount_path")
  if [[ "$io1" -le "$io2" ]] && [[ "$io1" -le "$io3" ]]; then
    ioavg=$(awk 'BEGIN{printf("%.0f", ('"$io2"' + '"$io3"')/2)}' | Bps_to_MiBps)
  elif [[ "$io2" -le "$io1" ]] && [[ "$io2" -le "$io3" ]]; then
    ioavg=$(awk 'BEGIN{printf("%.0f", ('"$io1"' + '"$io3"')/2)}' | Bps_to_MiBps)
  else
    ioavg=$(awk 'BEGIN{printf("%.0f", ('"$io1"' + '"$io2"')/2)}' | Bps_to_MiBps)
  fi
  outputdiskbench+=" loop $loop_mount $ioavg"
  if [[ "${ioavg%%.*}" -ge "180" ]]; then
    SSD=$(awk 'BEGIN{printf("%d",'"$SSD"'+'"$loop_mount"')}')
  else
    HDD=$(awk 'BEGIN{printf("%d",'"$HDD"'+'"$loop_mount"')}')
  fi
  echo -e "$outputdiskbench"
  echo -e ""
  # Fall through to scoring below (no exit here so scores are computed)
fi

if [[ "$loop_mount" == "" ]]; then
  lvm_mount=""
  raid_list=()
  disc__array=($(cd $HOME && LC_ALL=C lsblk -o NAME,SIZE,TYPE -b -n | grep ' disk' | \
    awk '{ if ($2 > 2147483648 && $1 != "mmcblk0" && $1 != "mmcblk0p1") print $1}'))

  for((i=0;i<${#disc__array[@]};i++)); do
    cd $HOME && lsblk -l -b -n /dev/${disc__array[i]} > /dev/null 2>&1
    if [ $? != 0 ]; then continue; fi

    disk_mount_check=$(cd $HOME && LC_ALL=C lsblk -l -b -n /dev/${disc__array[i]} | \
      egrep ' disk' | awk '{ if ($7 == "") print "no"; else print "yes"}')

    if [[ "$disk_mount_check" == "no" ]]; then
      lvm_mount=$(cd $HOME && LC_ALL=C lsblk -l -b /dev/${disc__array[i]} --sort SIZE | \
        egrep ' lvm| dm' | tail -n1 | awk '{ print $7 }')
      lvm_name=$(cd $HOME && LC_ALL=C lsblk -l -b /dev/${disc__array[i]} --sort SIZE | \
        egrep ' lvm| dm' | tail -n1 | awk '{ print $1 }')

      if [[ "$lvm_name" != "" ]]; then
        count=$(echo ${mount_list[@]} | tr ' ' '\n' | awk '$1 == "'"$lvm_mount"'"{print $0}' | wc -l)
        if [[ "$count" == "0" ]]; then mount_list+=("$lvm_mount"); else continue; fi
      fi
      if [[ "$lvm_name" != "" && "$lvm_mount" == "" ]]; then
        if [[ ! -d /.benchmark_test ]]; then sudo mkdir /.benchmark_test; fi
        sudo mount /dev/mapper/$lvm_name /.benchmark_test
      fi
      lvm_mount=$(cd $HOME && LC_ALL=C lsblk -l -b /dev/${disc__array[i]} --sort SIZE | \
        egrep ' lvm| dm' | tail -n1 | awk '{ print $7 }')
      if [[ "$lvm_mount" != "" ]]; then
        partition_output=$(cd $HOME && LC_ALL=C lsblk -l -b /dev/${disc__array[i]} --sort SIZE | \
          egrep ' lvm| dm' | tail -n1 | awk '{print $1 " " $4/(1024*1024*1024) }')
      else
        part_type_check=$(cd $HOME && LC_ALL=C lsblk -o NAME,TYPE,FSTYPE,SIZE -b -n \
          /dev/${disc__array[i]} --sort SIZE | egrep ' part' | egrep 'LVM2_member' | tail -n1 | wc -l)
        if [[ "$part_type_check" != "0" ]]; then continue; fi
        partition_output=$(cd $HOME && LC_ALL=C lsblk -l -b /dev/${disc__array[i]} --sort SIZE | \
          egrep ' raid' | tail -n1 | awk '{print $1 " " $4/(1024*1024*1024) }')
        if [[ "$partition_output" == "" ]]; then
          partition_output=$(cd $HOME && LC_ALL=C lsblk -l -b /dev/${disc__array[i]} --sort SIZE | \
            egrep ' part' | tail -n1 | awk '{print $1 " " $4/(1024*1024*1024) }')
        else
          partition_name=$(awk '{print $1}' <<< $partition_output)
          if [[ ! " ${raid_list[@]} " =~ " ${partition_name} " ]]; then
            raid_list+=("$partition_name")
          else
            continue
          fi
        fi
      fi
    else
      partition_output=$(cd $HOME && LC_ALL=C lsblk -l -b /dev/${disc__array[i]} --sort SIZE | \
        tail -n1 | awk '{print $1 " " $4/(1024*1024*1024) }')
    fi

    partition_name=$(awk '{print $1}' <<< $partition_output)
    partition_size=$(awk '{printf("%.2f",$2)}' <<< $partition_output)

    if [[ "$lvm_mount" == "" && "$raid_list" == "" ]]; then
      disk_size=$(cd $HOME && LC_ALL=C lsblk -l -b /dev/${disc__array[i]} --noheadings | \
        head -n1 | awk '{printf("%.2f",$4/(1024*1024*1024))}')
    else
      disk_size=$partition_size
    fi

    _did_mount=0
    if [[ "$lvm_mount" == "" ]]; then
      already_mounted=$(lsblk -ln /dev/$partition_name -o MOUNTPOINT 2>/dev/null | grep -v '^$' | head -1)
      if [[ "$already_mounted" != "" ]]; then
        mount_path="$HOME"
      else
        if [[ ! -d /.benchmark_test ]]; then sudo mkdir /.benchmark_test; fi
        sudo mount /dev/$partition_name /.benchmark_test && _did_mount=1
        mount_path="/.benchmark_test"
      fi
      available_space=$(LC_ALL=C df /dev/$partition_name | grep $partition_name | tail -n1 | \
        awk '{ if ($4 > 2097152) printf("%.2f",$4/(1024*1024)); else print "null"}')
    else
      available_space=$(LC_ALL=C df /dev/mapper/$partition_name | grep $partition_name | tail -n1 | \
        awk '{ if ($4 > 2097152) printf("%.2f",$4/(1024*1024)); else print "null"}')
    fi

    if [[ "$available_space" != "null" && "$available_space" != "" ]]; then
      if [[ "$lvm_mount" != "" ]]; then mount_path="$lvm_mount"; fi
      io1=$(dd_benchmark "$mount_path")
      io2=$(dd_benchmark "$mount_path")
      io3=$(dd_benchmark "$mount_path")
      if [[ "$io1" -le "$io2" ]] && [[ "$io1" -le "$io3" ]]; then
        ioavg=$(awk 'BEGIN{printf("%.0f", ('"$io2"' + '"$io3"')/2)}' | Bps_to_MiBps)
      elif [[ "$io2" -le "$io1" ]] && [[ "$io2" -le "$io3" ]]; then
        ioavg=$(awk 'BEGIN{printf("%.0f", ('"$io1"' + '"$io3"')/2)}' | Bps_to_MiBps)
      else
        ioavg=$(awk 'BEGIN{printf("%.0f", ('"$io1"' + '"$io2"')/2)}' | Bps_to_MiBps)
      fi
      outputdiskbench+=" ${disc__array[i]} $disk_size $ioavg"
      if [[ "${ioavg%%.*}" -ge "180" ]]; then
        SSD=$(awk 'BEGIN{printf("%d",'"$SSD"'+'"$disk_size"')}')
      else
        HDD=$(awk 'BEGIN{printf("%d",'"$HDD"'+'"$disk_size"')}')
      fi
    fi

    if [[ "$_did_mount" == "1" ]]; then
      sudo umount /.benchmark_test 2>/dev/null
      if [[ ! $(lsblk -l | grep "benchmark_test") ]]; then sudo rm -rf /.benchmark_test 2>/dev/null; fi
    fi
    if [[ $(lsblk -l | grep "benchmark_test") ]]; then
      sudo umount /.benchmark_test 2>/dev/null
      if [[ ! $(lsblk -l | grep "benchmark_test") ]]; then sudo rm -rf /.benchmark_test 2>/dev/null; fi
    fi
  done

  if [[ "$outputdiskbench" == "Disks Bench:" ]]; then
    df_direct_mount=$(LC_ALL=C df --output=source,fstype,size,avail,target | grep 'dev' | \
      awk '{ if ($5 == "/") printf("%s %.2f %.2f\n", $1,$3/(1024*1024),$4/(1024*1024))}')
    if [[ "$df_direct_mount" != "" ]]; then
      device_name=$(awk '{print $1}' <<< $df_direct_mount)
      partition_size=$(awk '{print $2}' <<< $df_direct_mount)
      mount_path="$HOME"
      io1=$(dd_benchmark "$mount_path")
      io2=$(dd_benchmark "$mount_path")
      io3=$(dd_benchmark "$mount_path")
      if [[ "$io1" -le "$io2" ]] && [[ "$io1" -le "$io3" ]]; then
        ioavg=$(awk 'BEGIN{printf("%.0f", ('"$io2"' + '"$io3"')/2)}' | Bps_to_MiBps)
      elif [[ "$io2" -le "$io1" ]] && [[ "$io2" -le "$io3" ]]; then
        ioavg=$(awk 'BEGIN{printf("%.0f", ('"$io1"' + '"$io3"')/2)}' | Bps_to_MiBps)
      else
        ioavg=$(awk 'BEGIN{printf("%.0f", ('"$io1"' + '"$io2"')/2)}' | Bps_to_MiBps)
      fi
      outputdiskbench+=" $device_name $partition_size $ioavg"
      if [[ "${ioavg%%.*}" -ge "180" ]]; then
        SSD=$(awk 'BEGIN{printf("%d",'"$SSD"'+'"$partition_size"')}')
      else
        HDD=$(awk 'BEGIN{printf("%d",'"$HDD"'+'"$partition_size"')}')
      fi
    fi
  fi
fi

# ---- Scoring --------------------------------------------------------
if [[ $status == "CUMULUS" ]]; then SCORE=1; fi
if [[ $status == "NIMBUS"  ]]; then SCORE=2; fi
if [[ $status == "STRATUS" ]]; then SCORE=3; fi

if [[ "$SSD" -lt 220 ]] || [[ "$SCORE" == 0 ]]; then status="FAILED"; fi

if [[ "$SSD" -ge 220 ]] && [[ "$SCORE" -ge 1 ]]; then
  status="CUMULUS"
  eps=$(LC_ALL=C sysbench cpu --cpu-max-prime=60000 --time=20 run 2>/dev/null | \
    grep 'events per second' | awk '{print $4*4}')
fi
if [[ "$HDD" -ge 9200 ]] && [[ "$SCORE" -ge 1 ]]; then
  status="THUNDER"
  eps=$(LC_ALL=C sysbench cpu --cpu-max-prime=60000 --time=20 run 2>/dev/null | \
    grep 'events per second' | awk '{print $4*4}')
fi
if [[ "$SSD" -ge 440 ]] && [[ "$SCORE" -ge 2 ]]; then
  status="NIMBUS"
  eps=$(LC_ALL=C sysbench cpu --cpu-max-prime=60000 --time=20 run 2>/dev/null | \
    grep 'events per second' | awk '{print $4*8}')
fi
if [[ "$SSD" -ge 880 ]] && [[ "$SCORE" -ge 3 ]]; then
  if [[ "${ioavg%%.*}" -ge "400" ]] && [[ "$(dpkg --print-architecture)" == "amd64" ]]; then
    status="STRATUS"
    eps=$(LC_ALL=C sysbench cpu --cpu-max-prime=60000 --time=20 run 2>/dev/null | \
      grep 'events per second' | awk '{print $4*16}')
  else
    status="NIMBUS"
    eps=$(LC_ALL=C sysbench cpu --cpu-max-prime=60000 --time=20 run 2>/dev/null | \
      grep 'events per second' | awk '{print $4*8}')
  fi
fi

if [[ "${eps%%.*}" -lt 240 ]];                                  then status="FAILED";  fi
if [[ "${eps%%.*}" -ge 240  && "$status" == "THUNDER"  ]]; then status="THUNDER";  fi
if [[ "${eps%%.*}" -ge 240  && "$status" == "CUMULUS"  ]]; then status="CUMULUS";  fi
if [[ "${eps%%.*}" -ge 640  && "$status" == "NIMBUS"   ]]; then status="NIMBUS";   fi
if [[ "${eps%%.*}" -ge 1520 && "$status" == "STRATUS"  ]]; then status="STRATUS";  fi

if [[ "$status" != "FAILED" ]]; then echo -e "| EPS: ${CYAN}${eps}${NC}"; fi

echo -e "-------------------------"
echo -e "| DISK BENCHMARK"
echo -e "-------------------------"
echo -e "| SSD: ${CYAN}${SSD}${NC}"
echo -e "| HDD: ${CYAN}${HDD}${NC}"
echo -e "| WRITESPEED: ${CYAN}${ioavg%%.*}${NC}"
echo -e "-------------------------"
if [[ "$status" != "FAILED" ]]; then
  echo -e "| Benchmark: ${GREEN}$status${NC}"
else
  echo -e "| Benchmark: ${RED}$status${NC}"
fi
echo -e "-------------------------"
