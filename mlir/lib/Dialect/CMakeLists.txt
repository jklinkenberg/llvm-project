add_subdirectory(Affine)
add_subdirectory(Arithmetic)
add_subdirectory(ArmNeon)
add_subdirectory(ArmSVE)
add_subdirectory(Async)
add_subdirectory(AMX)
add_subdirectory(Bufferization)
add_subdirectory(Complex)
add_subdirectory(ControlFlow)
add_subdirectory(DLTI)
add_subdirectory(EmitC)
add_subdirectory(Func)
add_subdirectory(GPU)
add_subdirectory(Linalg)
add_subdirectory(LLVMIR)
add_subdirectory(Math)
add_subdirectory(MemRef)
add_subdirectory(OpenACC)
add_subdirectory(OpenMP)
add_subdirectory(PDL)
add_subdirectory(PDLInterp)
add_subdirectory(Quant)
add_subdirectory(SCF)
add_subdirectory(Shape)
add_subdirectory(SparseTensor)
add_subdirectory(SPIRV)
add_subdirectory(Tensor)
add_subdirectory(Tosa)
add_subdirectory(Utils)
add_subdirectory(Vector)
add_subdirectory(X86Vector)

set(LLVM_OPTIONAL_SOURCES
  Traits.cpp
)

add_mlir_library(MLIRDialect
  Traits.cpp

  ADDITIONAL_HEADER_DIRS
  ${MLIR_MAIN_INCLUDE_DIR}/mlir/Dialect

  LINK_LIBS PUBLIC
  MLIRIR
  )
