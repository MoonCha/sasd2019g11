#/bin/sh

for i in {1..100}
do
    offset="0"
    sum=$(echo "group$offset$i" | sha256sum | sed -e 's/ -//g')
    sum=${sum: -9}
    while true;
    do
        sum=$(echo "group$offset$i" | sha256sum | sed -e 's/ -//g')
        sum=${sum: -9}
        offset+="0"
        val=${sum:0:1}
        if [ $((16#$val)) -lt 8 ]
        then
          break
        fi
    done
    echo $sum
    make LOCATION=0x$sum
    mv my_first_rop_chain student_bins/group_$i
    make clean
done