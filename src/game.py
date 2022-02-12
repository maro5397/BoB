# -*- coding: utf-8 -*-
from distutils.util import change_root
import numpy as np
from renju_rule import Renju_Rule
import os
from gomoku_lib import Gomoku

my_gomoku = Gomoku("34.64.183.225", 1234, True)

class Board(object):
    def __init__(self, **kwargs):
        self.width = int(kwargs.get('width', 15))
        self.height = int(kwargs.get('height', 15))
        self.n_in_row = int(kwargs.get('n_in_row', 5))
        self.players = [1, 2]  # player1 and player2

    def init_board(self, start_player=0) :
        self.order = start_player # order = 0 → 사람 선공(흑돌) / 1 → AI 선공(흑돌)
        self.current_player = self.players[start_player]  # current_player = 1 → 사람 / 2 → AI
        self.last_move, self.last_loc = -1, -1
        
        self.states, self.states_loc = {}, [[0] * self.width for _ in range(self.height)]
        self.forbidden_locations, self.forbidden_moves = [], []

    def move_to_location(self, move):
        h = move // self.width
        w = move % self.width
        return [h, w]

    def location_to_move(self, location):
        if len(location) != 2 : return -1
        h, w = location[0], location[1]
        move = h * self.width + w
        if move not in range(self.width * self.height) : return -1
        return move

    def current_state(self):
        square_state = np.zeros((4, self.width, self.height))
        if self.states:
            moves, players = np.array(list(zip(*self.states.items())))
            move_curr = moves[players == self.current_player]
            move_oppo = moves[players != self.current_player]
            square_state[0][move_curr // self.width, move_curr % self.height] = 1.0 #내가 둔 돌의 위치를 1로 표현
            square_state[1][move_oppo // self.width, move_oppo % self.height] = 1.0 #적이 둔 돌의 위치를 1로 표현
            square_state[2][self.last_move // self.width, self.last_move % self.height] = 1.0 #마지막 돌의 위치
            
        if len(self.states) % 2 == 0 : square_state[3][:, :] = 1.0  # indicate the colour to play
        
        return square_state[:, ::-1, :]

    def do_move(self, move):
        self.states[move] = self.current_player
        loc = self.move_to_location(move)
        self.states_loc[loc[0]][loc[1]] = 1 if self.is_you_black() else 2
        self.current_player = (self.players[0] if self.current_player == self.players[1] else self.players[1])
        self.last_move, self.last_loc = move, loc

    def has_a_winner(self):
        width = self.width
        height = self.height
        states = self.states
        n = self.n_in_row

        # moved : 이미 돌이 놓인 자리들
        moved = list(self.states.keys())
        if len(moved) < self.n_in_row * 2-1 : return False, -1

        for m in moved:
            h = m // width
            w = m % width
            player = states[m]
            #6목 흑은 승리하지 않음
            if (w in range(width - n + 1) and
                    len(set(states.get(i, -1) for i in range(m, m + n))) == 1):
                return True, player

            if (h in range(height - n + 1) and
                    len(set(states.get(i, -1) for i in range(m, m + n * width, width))) == 1):
                return True, player

            if (w in range(width - n + 1) and h in range(height - n + 1) and
                    len(set(states.get(i, -1) for i in range(m, m + n * (width + 1), width + 1))) == 1):
                return True, player

            if (w in range(n - 1, width) and h in range(height - n + 1) and
                    len(set(states.get(i, -1) for i in range(m, m + n * (width - 1), width - 1))) == 1):
                return True, player
        
        return False, -1

    def game_end(self):
        win, winner = self.has_a_winner()
        if win : return True, winner
        elif len(self.states) == self.width*self.height : return True, -1
        return False, -1

    def get_current_player(self):
        return self.current_player
    
    def set_forbidden(self) :
        # forbidden_locations : 흑돌 기준에서 금수의 위치
        rule = Renju_Rule(self.states_loc, self.width)
        if self.order == 0 : self.forbidden_locations = rule.get_forbidden_points(stone=1)
        else : self.forbidden_locations = rule.get_forbidden_points(stone=2)
        self.forbidden_moves = [self.location_to_move(loc) for loc in self.forbidden_locations]
        
    def is_you_black(self) :
        if self.order == 0 and self.current_player == 1 : return True
        elif self.order == 1 and self.current_player == 2 : return True
        else : return False


class Game(object):
    def __init__(self, board, **kwargs):
        self.board = board

    def graphic(self, board, player1, player2):
        width = board.width
        height = board.height

        os.system('cls')
        
        print()
        if board.order == 0 : 
            print("흑돌(●) : 플레이어")
            print("백돌(○) : AI")
        else :
            print("흑돌(●) : AI")
            print("백돌(○) : 플레이어")
        print("--------------------------------\n")
        
        if board.current_player == 1 : print("당신의 차례입니다.\n")
        else : print("AI가 수를 두는 중...\n")
            
        row_number = [' 0 ',' 1 ',' 2 ',' 3 ',' 4 ',' 5 ',' 6 ',' 7 ',' 8 ',' 9 ','10 ','11 ','12 ','13 ','14 ']
        print('   ', end='')
        for i in range(height) : print(row_number[i], end='')
        print()
        for i in range(height):
            print(row_number[i], end='')
            for j in range(width):
                loc = i * width + j
                p = board.states.get(loc, -1)
                if p == player1 : print(' ● ' if board.order == 0 else ' ○ ', end='')
                elif p == player2 : print(' ○ ' if board.order == 0 else ' ● ', end='')
                elif board.is_you_black() and (i,j) in board.forbidden_locations : print(' X ', end='')
                else : print('   ', end='')
            print()
        if board.last_loc != -1 :
            print(f"마지막 돌의 위치 : ({board.last_loc[0]},{board.last_loc[1]})\n")

    def start_play_offline(self, player1, player2, start_player=0, is_shown=1):
        self.board.init_board(start_player)
        p1, p2 = self.board.players
        player1.set_player_ind(p1)
        player2.set_player_ind(p2)
        players = {p1: player1, p2: player2}
        while True:
            # 흑돌일 때, 금수 위치 확인하기
            if self.board.is_you_black() : self.board.set_forbidden()
            if is_shown : self.graphic(self.board, player1.player, player2.player)
                
            current_player = self.board.get_current_player()
            player_in_turn = players[current_player]
            
            if current_player == 1 : # 사람일 때
                move = player_in_turn.get_action(self.board)
            else : # AI일 때
                move = player_in_turn.get_action(self.board)
                
            self.board.do_move(move)
            end, winner = self.board.game_end()
            if end:
                if is_shown:
                    self.graphic(self.board, player1.player, player2.player)
                    if winner != -1 : print("Game end. Winner is", players[winner])
                    else : print("Game end. Tie")
                return winner
            
    # start_player = 0 → 사람 선공 / 1 → AI 선공
    def start_play_online_human(self, player, challenger, is_shown=1):
        if my_gomoku.connect():
            if my_gomoku.color == 'black':
                order = 0
            else:
                order = 1
        self.board.init_board(order)
        p1, p2 = self.board.players
        player.set_player_ind(p1)
        challenger.set_player_ind(p2)
        players = {p1: player, p2: challenger}
        
        my_gomoku.ready()
        updateinit = my_gomoku.update_or_end()
        if updateinit[0]:
            if updateinit[1] == 2 and updateinit[3] == 0:
                if updateinit[2] == 0:
                    move = player.get_action(self.board)
                    location = self.board.move_to_location(move)
                    my_gomoku.put(location[1], location[0])
                    self.board.do_move(move)
                else:
                    pass
        xfilter = 0b11110000
        yfilter = 0b00001111
        while True:
            if self.board.is_you_black() : self.board.set_forbidden()
            if is_shown : self.graphic(self.board, player.player, challenger.player)
            
            res = my_gomoku.update_or_end()
            if res[0]:
                if res[1] == 2: #update
                    current_player = res[2]
                    player_in_turn = players[current_player]
                    if current_player == 1: #my turn
                        xy = res[3]
                        x = (xy & xfilter) >> 4
                        y = xy&yfilter
                        location = [y, x]
                        move = player_in_turn.get_action(self.board, location)
                        self.board.do_move(move)
                        move = player_in_turn.get_action(self.board)
                        location = self.board.move_to_location(move)
                        my_gomoku.put(location[1], location[0])
                        self.board.do_move(move)
                        continue
                    else: #challenger turn
                        continue
                elif res[1] == 4: #end
                    if is_shown: self.graphic(self.board, player.player, challenger.player)
                    if res[2] == 1:
                        print("You win!")
                    else:
                        print("You lose!")
                    print("code:", res[3])
                    return
            else:
                print("error: False return")
                return

    def start_self_play(self, player, is_shown=0, temp=1e-3):
        """ 스스로 자가 대국하여 학습 데이터(state, mcts_probs, z) 생성 """
        self.board.init_board()
        p1, p2 = self.board.players
        states, mcts_probs, current_players = [], [], []
        while True:
            # 흑돌일 때, 금수 위치 확인하기
            if self.board.is_you_black() : self.board.set_forbidden()
            if is_shown : self.graphic(self.board, p1, p2)
            
            move, move_probs = player.get_action(self.board, temp=temp, return_prob=1)
            # store the data
            states.append(self.board.current_state())
            mcts_probs.append(move_probs)
            current_players.append(self.board.current_player)
            
            # perform a move
            self.board.do_move(move)
                
            end, winner = self.board.game_end()
            if end:
                # winner from the perspective of the current player of each state
                winners_z = np.zeros(len(current_players))
                if winner != -1:
                    winners_z[np.array(current_players) == winner] = 1.0
                    winners_z[np.array(current_players) != winner] = -1.0
                # reset MCTS root node
                player.reset_player()
                if is_shown:
                    self.graphic(self.board, p1, p2)
                    if winner != -1 : print("Game end. Winner is player:", winner)
                    else : print("Game end. Tie")
                return winner, zip(states, mcts_probs, winners_z)
