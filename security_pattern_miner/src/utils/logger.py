from logging import getLogger, StreamHandler, DEBUG, INFO, WARNING, ERROR, CRITICAL, Formatter

logger = getLogger(__name__)
logger.setLevel(DEBUG)

handler = StreamHandler()
handler.setLevel(DEBUG)

formatter = Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

logger.addHandler(handler)