    .data
pr: .asciz "%d\n"
sc: .asciz "%d"
    .text
    .global func
    .global main
func:
    pushl   %ebp
    movl    %esp, %ebp
    
    pushl   %esi
    pushl   %edi
    pushl   %ebx
    
    subl    $4, %esp
    movl    %esp, %ebx // в %ebx лежит адрес %ebp -4-4-4-4 =>(%ebx) == -16(%ebp), считаем сюда n
    pushl   %ebx
    pushl   $sc
    call    scanf
    addl    $8, %esp
    //сейчас буду творить магию, потому что  mull $4 не работает, значит, надо вместо n добиться 4*n на том же месте
    movl    -16(%ebp), %eax
    movl    $4, %esi
    mull    %esi
    movl    %eax, -16(%ebp)
    //отлично, в -16(%ebp) n*4. Если нам дали меньше 2 чисел, т. е. одно или 0, даже но попытаемся их прочитать.
    cmpl    $4, -16(%ebp) 
    jz read_1
    cmpl    $0, -16(%ebp)
    jz nth
    //здесь нам уже не нужен %ebx, поэтому я потом использую его чтоб запомнить где я нахожусь
    //до выделения памяти на стеке под массив, чтоб потом уже прибавлять к этому адресу смещение 
pre_read:
    movl    -16(%ebp), %edi // в %edi кол-во байт которе надо выделить на стеке, его будем менять
    subl    %edi, %esp
    movl    %esp, %ebx
read:
    testl   %edi, %edi
    jz pre_calc
    pushl   %ebx // (%ebx) == -4-4-4-4-%edi(%ebp)
    pushl   $sc
    call scanf //(%ebx) = считанное число, сам %ebx - указатель на место в стеке
    addl    $8, %esp
    subl    $4, %edi // в цикле уменьшаем %edi, значит, увеличиваем значение %ebx
    addl    $4, %ebx // похоже на то, что так мне удастся прочитать массив с конца(первое считанное вверху стека, последнее - над ячейкой, в которой лежит кол-во чисел)
    jmp read
pre_calc:
    movl    -16(%ebp), %edi // в %edi кол-во байт которе надо выделленных на стеке
//как мы будем считать: попробуем к тому, что лежит ниже, прибавлять то, что лежит выше: ко второму - первое, ..., к последнему - предпоследнее. потом надо будет выводить всё, кроме первого и вывод будет почти такой же как ввод
    subl    $4, %edi
//    subl    %edi, %ebx // -4(%ebx) - 1е считанное число, (%ebx) - 2е 
//сейчас (%ebx) == -16(%ebp), значит чтоб оказаться на последнем считанном числе надо подняться вверх на ячейку
    subl    $4, %ebx 
calc:
    testl   %edi, %edi
    jz pre_write
    movl    (%ebx), %esi
    addl    -4(%ebx), %esi
    movl    %esi, (%ebx)
    subl    $4, %ebx
    subl    $4, %edi
    jmp calc

pre_write:
    movl    -16(%ebp), %edi // в %edi кол-во байт которе выделили на стеке, и еди мы имеем право менять менять
    subl    $4, %edi
    addl    $4, %ebx
//    subl    %edi, %ebx // -4(%ebx) - 1е считанное число, оно больше нам не нужно, в (%ebx) - 2е, печатаем начиная с него
write:
    testl   %edi, %edi
    jz smth_done
    pushl   (%ebx)
    pushl   $pr
    call printf //(%ebx) = считанное число, сам %ebx - указатель на место в стеке
    addl    $8, %esp
    subl    $4, %edi // в цикле уменьшаем %edi, значит, увеличиваем значение %ebx
    addl    $4, %ebx // похоже на то, что так мне удастся прочитать массив с конца(первое считанное вверху стека, последнее - над ячейкой, в которой лежит кол-во чисел)
    jmp write

smth_done:
    movl    -16(%ebp), %edi
    addl    %edi, %esp
    addl    $4, %esp
    jmp end

nth:
    addl $4, %esp
    jmp end
    
read_1:
    subl    $4, %esp
    movl    %esp, %esi
    pushl   %esi
    pushl   $sc
    call scanf
    addl    $16, %esp
    jmp end
end:
    popl    %ebx
    popl    %edi
    popl    %esi
    movl    %ebp, %esp
    popl    %ebp
    ret

main:
    call func
