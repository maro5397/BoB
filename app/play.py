import sys, os
sys.path.append("../src")

import pickle
from game import Board, Game
from mcts_alphaZero import MCTSPlayer
from policy_value_net_numpy import PolicyValueNetNumpy

class Human(object):
    def __init__(self):
        self.player = None

    def set_player_ind(self, p):
        self.player = p

    def get_action(self, board):
        try:
            print("돌을 둘 좌표를 입력하세요.")
            location = input()
            if isinstance(location, str) : location = [int(n, 10) for n in location.split(",")]
            move = board.location_to_move(location)
        except Exception as e : move = -1
            
        if move == -1 or move in board.states.keys() :
            print("다시 입력하세요.")
            move = self.get_action(board)
        elif board.is_you_black() and tuple(location) in board.forbidden_locations :
            print("금수 자리에 돌을 놓을 수 없습니다.")
            move = self.get_action(board)
            
        return move

    def __str__(self):
        return "Human {}".format(self.player)
    
class Challenger(object):
    def __init__(self):
        self.player = None

    def set_player_ind(self, p):
        self.player = p

    def get_action(self, board, location):
        try:
            move = board.location_to_move(location)
        except Exception as e : move = -1
        return move

    def __str__(self):
        return "Human {}".format(self.player)


def get_AI_player(width, height):
    print("난이도(정책망의 학습 횟수) 입력: ", end='')
    hard = int(input())
    model_file = f'./model/policy_15_{hard}.model'
    # 이미 제공된 model을 불러와서 학습된 policy_value_net을 얻는다.
    policy_param = pickle.load(open(model_file, 'rb'), encoding='bytes')
    best_policy = PolicyValueNetNumpy(width, height, policy_param)
    return MCTSPlayer(best_policy.policy_value_fn, c_puct=5, n_playout=400) # n_playout값 : 성능
        

def online_game_for_AI(n, width, height):
    board = Board(width=width, height=height, n_in_row=n)
    game = Game(board)
    ai_player = get_AI_player(width, height)
    challenger = Challenger()
    game.start_play_offline(ai_player, challenger, is_shown=1) 
    
    
def online_game_for_human(n, width, height):
    board = Board(width=width, height=height, n_in_row=n)
    game = Game(board)
    human = Human()
    challenger = Challenger()
    game.start_play_offline(human, challenger, is_shown=1) 


def offline_game(n, width, height):
    print("선공(흑)인 경우에 0, 후공(백)인 경우에 1을 입력")
    order = int(input())
    if order not in [0,1] : return "강제 종료"
    board = Board(width=width, height=height, n_in_row=n)
    game = Game(board)
    mcts_player = get_AI_player(width, height)
    human = Human()
    game.start_play_offline(human, mcts_player, start_player=order, is_shown=1) 


def run():
    n = 5
    width, height = 15, 15
    print("온라인 게임이라면 0을, 오프라인 게임이라면 1을 입력: ", end='')
    game_option = int(input())
    if game_option == 1:
        offline_game(n, width, height)
    else:
        print("직접 플레이한다면 0을, 인공지능으로 플레이한다면 1을 입력: ", end='')
        player_option = int(input())
        if player_option == 0:
            online_game_for_human(n, width, height)
        else:
            online_game_for_AI(n, width, height)


if __name__ == '__main__':
    run()