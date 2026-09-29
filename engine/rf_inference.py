#!/usr/bin/env python3
from __future__ import annotations

import json
from typing import Dict, List, Sequence


class ContentRandomForest:
    def __init__(self, model: dict):
        self.classes: List[str] = model["classes"]
        self.features: List[str] = model["features"]
        self.impute_medians: Dict[str, float] = model["impute_medians"]
        self.trees: List[dict] = model["trees"]

    @classmethod
    def load(cls, path: str) -> "ContentRandomForest":
        with open(path, "r", encoding="utf-8") as f:
            return cls(json.load(f))

    def _vector(self, feats: Dict[str, object]) -> List[float]:
        """Feature vector in model order; missing values imputed with training medians."""
        vec = []
        for name in self.features:
            v = feats.get(name)
            if v is None or isinstance(v, bool):
                # Exclude bool from the None guard: True/False are valid 0/1 values.
                v = self.impute_medians.get(name, 0.0) if v is None else float(v)
            else:
                try:
                    v = float(v)
                except (TypeError, ValueError):
                    v = self.impute_medians.get(name, 0.0)
            vec.append(v)
        return vec

    def _walk_tree(self, tree: dict, vec: List[float]) -> List[float]:
        node = 0
        children_left = tree["children_left"]
        children_right = tree["children_right"]
        feature = tree["feature"]
        threshold = tree["threshold"]
        leaf_value = tree["leaf_value"]
        while children_left[node] != -1:
            if vec[feature[node]] <= threshold[node]:
                node = children_left[node]
            else:
                node = children_right[node]
        return leaf_value[node]

    def predict_proba(self, feats: Dict[str, object]) -> Dict[str, float]:
        vec = self._vector(feats)
        totals = [0.0] * len(self.classes)
        for tree in self.trees:
            leaf = self._walk_tree(tree, vec)
            for i, p in enumerate(leaf):
                totals[i] += p
        n = len(self.trees)
        return {c: totals[i] / n for i, c in enumerate(self.classes)}

    def predict(self, feats: Dict[str, object]) -> Dict[str, object]:
        proba = self.predict_proba(feats)
        label = max(proba, key=proba.get)
        return {"label": label, "confidence": proba[label], "proba": proba}
