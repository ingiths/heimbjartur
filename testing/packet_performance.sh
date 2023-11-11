echo $1

calculate_average() {
  local -n numbers=$1 # -n option is used for nameref to create a reference to the actual array
  local sum=0
  local count=${#numbers[@]}

  echo $numbers $sum $count

  for num in "${numbers[@]}"; do
    sum=$((sum + num))
  done

  # Calculate and return the average
  echo "Average of ${numbers[*]} is: $((sum / count))"
}

noeBPF=()
simpleeBPF=()
complexeBPF=()

for i in $(seq 1 3)
do
	echo "Loop $i"
	noeBPF+=($(sudo ./heimbjartur_packet_performance_no_ebpf multiple $1 | grep elapsed | awk '{print $3}'))

	simpleeBPF+=($(sudo ./heimbjartur_packet_performance_with_ebpf_no_logic --binary kprobe_no_logic multiple $1 | grep elapsed | awk '{print $3}'))

  	complexeBPF+=($(sudo ./heimbjartur_packet_performance_with_ebpf --binary kprobe_logic multiple $1 | grep elapsed | awk '{print $3}'))
done

calculate_average noeBPF
calculate_average simpleeBPF
calculate_average complexeBPF