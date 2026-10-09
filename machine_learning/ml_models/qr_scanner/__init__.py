# QR Scanner ML Module
from .preprocess import QRPreprocessor
from .predict import QRScanner


def __getattr__(name):
	if name == 'train':
		from .train import train
		return train
	raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = ['QRPreprocessor', 'QRScanner', 'train']