#/bin/sh

TOKEN_ARGS=""
if [ -f flatsat.token ]; then
  TOKEN_ARGS="--host ws://umbilical.flatsat.space --token $(cat flatsat.token)"
fi

exec probe-rs run --chip STM32H723VG $TOKEN_ARGS "$@"
