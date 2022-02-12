# [알파제로(AlphaGo Zero)]의 구현 방식을 모방한 오목 인공지능(AI) 구현

## 오픈소스코드를 적극 활용
- [An implementation of the AlphaZero algorithm for Gomoku](https://github.com/junxiaosong/AlphaZero_Gomoku)

## 방법론
사용한 주요 방법론은 다음과 같이 3가지이다.
- 정책망(Policy Network)
  - 알파고(AlphaGo)에서 사용된 방법론으로, 현재 오목판의 상태(state)를 입력받아 각 위치에 대한 기댓값을 계산합니다.
  - 기댓값이 크다는 것은 자신 또는 상대가 착수하기 좋은 위치를 의미합니다.
- 자가 대국(self-play)을 통한 학습
  - 알파고 제로(AlphaGo Zero)에서 사용된 방법론으로, 자가 대국을 통해서 생성한 플레이 데이터만을 사용하여 정책망을 학습합니다.
  - 인간의 플레이 데이터를 전혀 사용하지 않았음에도, 알파고 제로는 알파고보다 뛰어난 성능을 보여주었습니다.
- MCTS(Monte Carlo Tree Search : 몬테카를로 트리 탐색) 알고리즘
  - 알파고와 알파고 제로에서 사용된 방법론으로, 다양한 경우의 수를 탐색하여 최종적으로 착수 위치를 결정합니다.
