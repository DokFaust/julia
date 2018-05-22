function mysum_slow(a)
    s = 0
    for x in a
        s += x
    end
    return s
end

mysum_slow([3,4,5])

mysum_slow([3.3,4,5])

function mysum_fast(a)
    s = zero(eltype(a))
    for x in a
        s += x
    end
    return s
end

mysum_fast([3,4,5])
mysum_fast([3.3,4,5])
